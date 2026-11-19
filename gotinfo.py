"""gotinfo.local — per-process network monitor for the Windows console.

Processes tab: live down/up per process + totals since launch. Enter = details.
Ports tab: every open TCP/UDP port, owner, rx/tx + totals since launch.
Per-process bytes come from ETW (netetw.py) and need admin; without it you
still get NIC totals and the open-port/connection list.
"""
from __future__ import annotations

import ctypes
import os
import shutil
import socket
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import psutil
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Sparkline, Static, TabbedContent, TabPane

from netetw import Ledger, NetTrace

REFRESH = 1.0
HISTORY = 120


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Elevated relaunch; True if UAC accepted. Absolute paths: elevated processes start in System32."""
    frozen = getattr(sys, "frozen", False)
    script = os.path.abspath(sys.argv[0])
    cwd = os.path.dirname(script)
    params = "" if frozen else f'"{script}"'
    exe = sys.executable
    wt = shutil.which("wt")
    if wt:  # conhost's font lacks the block glyphs the sparklines use; Windows Terminal has them
        exe, params = wt, f'-d "{cwd}" "{sys.executable}" {params}'
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, cwd, 1)
    return rc > 32


def fmt_bytes(n: float) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def fmt_rate(n: float) -> str:
    return "" if n < 1 else fmt_bytes(n) + "/s"


def rates(cur: dict, prev: dict, dt: float) -> dict:
    """{key: (rx, tx)} totals -> {key: (rx/s, tx/s)}."""
    out = {}
    for k, (rx, tx) in cur.items():
        prx, ptx = prev.get(k, (0, 0))
        out[k] = ((rx - prx) / dt, (tx - ptx) / dt)
    return out


def by_port(flows: dict) -> dict:
    """flows {(pid, proto, lport, raddr, rport): (rx, tx)} -> {(proto, lport, pid): (rx, tx)}."""
    out = defaultdict(lambda: [0, 0])
    for (pid, proto, lport, _r, _rp), (rx, tx) in flows.items():
        c = out[(proto, lport, pid)]
        c[0] += rx
        c[1] += tx
    return {k: tuple(v) for k, v in out.items()}


_names: dict[int, str] = {0: "Idle", 4: "System"}


def pname(pid: int) -> str:
    if pid not in _names:  # ponytail: never evicted; PID reuse can show a stale name for a dead process
        try:
            _names[pid] = psutil.Process(pid).name()
        except Exception:
            return "?"
    return _names[pid]


_rdns: dict[str, str] = {}
_pool = ThreadPoolExecutor(4)


def rdns(ip: str) -> str:
    """Reverse DNS, resolved in the background; '' until known."""
    if ip not in _rdns:
        _rdns[ip] = ""

        def work():
            try:
                _rdns[ip] = socket.gethostbyaddr(ip)[0]
            except Exception:
                _rdns[ip] = "-"
        _pool.submit(work)
    return _rdns[ip]


def proto_of(c) -> str:
    return "TCP" if c.type == socket.SOCK_STREAM else "UDP"


CSS = """
#hdr { height: 3; padding: 0 1; }
#hdr Static { width: 1fr; }
#spark { height: 3; }
#spark Sparkline { width: 1fr; margin: 0 1; }
#sp-down > .sparkline--max-color { color: $success; }
#sp-up > .sparkline--max-color { color: $warning; }
#banner { background: $error; color: $text; padding: 0 1; height: auto; }
DataTable { height: 1fr; }
DetailScreen { align: center middle; }
#detail { width: 95%; height: 90%; border: thick $accent; background: $surface; padding: 0 1; }
#dinfo { height: auto; }
"""


class DetailScreen(ModalScreen):
    BINDINGS = [Binding("escape,q,enter", "app.pop_screen", "Close")]

    def __init__(self, pid: int):
        super().__init__()
        self.pid = pid

    def compose(self) -> ComposeResult:
        with Vertical(id="detail"):
            yield Static(id="dinfo")
            yield DataTable(id="dflows", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_data_table_row_selected(self, event):
        event.stop()  # Enter on a flow row closes, never re-opens a detail screen
        self.app.pop_screen()

    def on_mount(self):
        t = self.query_one("#dflows", DataTable)
        t.add_columns("Proto", "Local", "Remote", "Host", "State", "↓/s", "↑/s", "↓ total", "↑ total")
        self.refresh_detail()
        self.set_interval(REFRESH, self.refresh_detail)

    def refresh_detail(self):
        app: GotInfo = self.app
        pid = self.pid
        lines = [f"[b]{pname(pid)}[/b]  pid {pid}"]
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                lines.append(f"exe:   {p.exe()}")
                lines.append(f"cmd:   {' '.join(p.cmdline())[:400]}")
                lines.append(f"user:  {p.username()}   started {datetime.fromtimestamp(p.create_time()):%Y-%m-%d %H:%M:%S}"
                             f"   mem {fmt_bytes(p.memory_info().rss)}   threads {p.num_threads()}")
        except psutil.AccessDenied:
            lines.append("(details need admin)")
        except psutil.NoSuchProcess:
            lines.append("[red](process has exited)[/red]")
        rx, tx = app.pid_tot.get(pid, (0, 0))
        drx, dtx = app.pid_rate.get(pid, (0, 0))
        lines.append(f"since launch: ↓ {fmt_bytes(rx)}  ↑ {fmt_bytes(tx)}     now: ↓ {fmt_rate(drx) or '0'}  ↑ {fmt_rate(dtx) or '0'}")
        self.query_one("#dinfo", Static).update("\n".join(lines))

        # Merge ETW flows with live sockets so idle connections and listeners show too.
        rows = {}
        for (fpid, proto, lport, raddr, rport), tot in app.flow_tot.items():
            if fpid == pid:
                rows[(proto, lport, raddr, rport)] = ["", tot, app.flow_rate.get((fpid, proto, lport, raddr, rport), (0, 0))]
        udp_bound = set()
        for c in app.conns:
            if c.pid != pid:
                continue
            if proto_of(c) == "UDP":
                udp_bound.add(c.laddr.port)
            k = (proto_of(c), c.laddr.port, c.raddr.ip if c.raddr else "", c.raddr.port if c.raddr else 0)
            rows.setdefault(k, ["", (0, 0), (0, 0)])[0] = c.status if c.status != "NONE" else "bound"
        for (proto, lport, raddr, _), row in rows.items():  # psutil UDP sockets have no remote; still bound = live
            if proto == "UDP" and raddr and not row[0] and lport in udp_bound:
                row[0] = "active"
        t = self.query_one("#dflows", DataTable)
        t.clear()
        for (proto, lport, raddr, rport), (state, (rx, tx), (drx, dtx)) in sorted(rows.items(), key=lambda kv: -sum(kv[1][1])):
            remote = f"{raddr}:{rport}" if raddr else "*"
            t.add_row(proto, str(lport), remote, rdns(raddr) if raddr else "", state or "closed",
                      fmt_rate(drx), fmt_rate(dtx), fmt_bytes(rx), fmt_bytes(tx))


SORTS = ["↓/s", "↑/s", "↓ total", "↑ total"]


class GotInfo(App):
    TITLE = "gotinfo.local"
    CSS = CSS
    BINDINGS = [
        Binding("1", "tab('procs')", "Processes"),
        Binding("2", "tab('ports')", "Ports"),
        Binding("s", "sort", "Sort"),
        Binding("c", "closed", "Hide/show closed"),
        Binding("enter", "detail", "Details", show=True),
        Binding("a", "admin", "Run as admin", show=not is_admin()),
        Binding("r", "reset", "Reset totals"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self.ledger = Ledger()
        self.trace = NetTrace(self.ledger)
        self.traced = is_admin() and self.trace.start()
        self.sort = 0
        self.hide_closed = False
        self.pid_tot, self.pid_rate, self.flow_tot, self.flow_rate = {}, {}, {}, {}
        self.port_prev, self.conns = {}, []
        self.prev_t = time.monotonic()
        self.nic0 = self.nic_prev = psutil.net_io_counters()
        self.hist_down, self.hist_up = [0.0] * HISTORY, [0.0] * HISTORY

    def compose(self) -> ComposeResult:
        if not self.traced:
            why = self.trace.error or "not elevated"
            yield Static(f"Per-process bytes unavailable ({why}). Press [b]a[/b] to relaunch as admin.", id="banner")
        with Horizontal(id="hdr"):
            yield Static(id="hdr-down")
            yield Static(id="hdr-up")
        with Horizontal(id="spark"):
            yield Sparkline(self.hist_down, id="sp-down")
            yield Sparkline(self.hist_up, id="sp-up")
        with TabbedContent(initial="procs"):
            with TabPane("Processes [1]", id="procs"):
                yield DataTable(id="tprocs", cursor_type="row", zebra_stripes=True)
            with TabPane("Ports [2]", id="ports"):
                yield DataTable(id="tports", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self):
        self.query_one("#tprocs", DataTable).add_columns("PID", "Process", "↓/s", "↑/s", "↓ total", "↑ total", "Conns")
        self.query_one("#tports", DataTable).add_columns("Proto", "Local", "State", "PID", "Process", "↓/s", "↑/s", "↓ total", "↑ total")
        self.tick()
        self.set_interval(REFRESH, self.tick)

    def on_unmount(self):
        self.trace.stop()

    # ── data ──
    def tick(self):
        now = time.monotonic()
        dt = max(now - self.prev_t, 1e-3)
        self.prev_t = now

        nic = psutil.net_io_counters()
        down = (nic.bytes_recv - self.nic_prev.bytes_recv) / dt
        up = (nic.bytes_sent - self.nic_prev.bytes_sent) / dt
        self.nic_prev = nic
        self.hist_down = self.hist_down[1:] + [down]
        self.hist_up = self.hist_up[1:] + [up]
        self.query_one("#hdr-down", Static).update(
            f"[b green]↓ {fmt_bytes(down)}/s[/]   total {fmt_bytes(nic.bytes_recv - self.nic0.bytes_recv)}   peak {fmt_bytes(max(self.hist_down))}/s")
        self.query_one("#hdr-up", Static).update(
            f"[b yellow]↑ {fmt_bytes(up)}/s[/]   total {fmt_bytes(nic.bytes_sent - self.nic0.bytes_sent)}   peak {fmt_bytes(max(self.hist_up))}/s"
            f"   [dim]({'per-process: ETW' if self.traced else 'NIC only'})[/]")
        self.query_one("#sp-down", Sparkline).data = self.hist_down
        self.query_one("#sp-up", Sparkline).data = self.hist_up

        pid_tot, flow_tot = self.ledger.snapshot()
        self.pid_rate, self.flow_rate = rates(pid_tot, self.pid_tot, dt), rates(flow_tot, self.flow_tot, dt)
        self.pid_tot, self.flow_tot = pid_tot, flow_tot
        try:
            self.conns = psutil.net_connections("inet")
        except psutil.AccessDenied:
            self.conns = []
        self.fill_procs()
        self.fill_ports(dt)

    def sort_key(self, rate, tot):
        return -[rate[0], rate[1], tot[0], tot[1]][self.sort]

    @staticmethod
    def refill(t: DataTable, rows: list):
        """rows: [(key, cells)] — redraw keeping the cursor on the same key."""
        cur = None
        if t.row_count:
            try:
                cur = t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
            except Exception:
                pass
        sx, sy = t.scroll_x, t.scroll_y
        t.clear()
        for key, cells in rows:
            t.add_row(*cells, key=key)
        if cur is not None:
            try:
                t.move_cursor(row=t.get_row_index(cur), scroll=False)
            except Exception:
                pass
        t.scroll_to(sx, sy, animate=False)  # keep the user's wheel position across the 1s rebuild

    def fill_procs(self):
        nconn = defaultdict(int)
        for c in self.conns:
            if c.pid:
                nconn[c.pid] += 1
        rows = []
        for pid in set(self.pid_tot) | set(nconn):
            tot, rate = self.pid_tot.get(pid, (0, 0)), self.pid_rate.get(pid, (0, 0))
            rows.append((self.sort_key(rate, tot), pid, [str(pid), pname(pid), fmt_rate(rate[0]), fmt_rate(rate[1]),
                                                           fmt_bytes(tot[0]), fmt_bytes(tot[1]), str(nconn.get(pid, ""))]))
        rows.sort(key=lambda r: (r[0], r[2][1].lower()))
        self.refill(self.query_one("#tprocs", DataTable), [(str(pid), cells) for _, pid, cells in rows])

    def fill_ports(self, dt):
        ports = by_port(self.flow_tot)
        prate = rates(ports, self.port_prev, dt)
        self.port_prev = ports
        state: dict = {}
        for c in self.conns:
            k = (proto_of(c), c.laddr.port, c.pid or 0)
            s = state.setdefault(k, {"addr": c.laddr.ip, "listen": False, "n": 0})
            if c.status == "LISTEN" or (s["n"] == 0 and not c.raddr and proto_of(c) == "UDP"):
                s["listen"] = True
            if c.raddr:
                s["n"] += 1
        rows = []
        for k in set(state) | set(ports):
            proto, lport, pid = k
            s = state.get(k)
            if s is None and self.hide_closed:
                continue
            if s is None:
                label, addr = "closed", ""
            else:
                bits = (["LISTEN" if proto == "TCP" else "bound"] if s["listen"] else []) + ([f"{s['n']} conn"] if s["n"] else [])
                label, addr = " + ".join(bits) or "open", s["addr"]
            tot, rate = ports.get(k, (0, 0)), prate.get(k, (0, 0))
            local = f"{addr}:{lport}" if addr else str(lport)
            rows.append((self.sort_key(rate, tot), lport, k, [proto, local, label, str(pid), pname(pid), fmt_rate(rate[0]),
                                                               fmt_rate(rate[1]), fmt_bytes(tot[0]), fmt_bytes(tot[1])]))
        rows.sort(key=lambda r: (r[0], r[1]))
        self.refill(self.query_one("#tports", DataTable), [("|".join(map(str, k)), cells) for _, _, k, cells in rows])

    # ── actions ──
    def action_tab(self, tab: str):
        self.query_one(TabbedContent).active = tab
        self.query_one(f"#t{tab}", DataTable).focus()

    def action_sort(self):
        self.sort = (self.sort + 1) % len(SORTS)
        self.notify(f"Sort: {SORTS[self.sort]}", timeout=1.5)
        self.fill_procs()
        self.fill_ports(REFRESH)

    def action_closed(self):
        self.hide_closed = not self.hide_closed
        self.notify(f"Closed ports {'hidden' if self.hide_closed else 'shown'}", timeout=1.5)
        self.fill_ports(REFRESH)

    def action_detail(self):
        tc = self.query_one(TabbedContent)
        t = self.query_one(f"#t{tc.active}", DataTable)
        if not t.row_count:
            return
        key = t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
        pid = int(key) if tc.active == "procs" else int(key.split("|")[2])
        self.push_screen(DetailScreen(pid))

    def on_data_table_row_selected(self, event):
        if event.data_table.id in ("tprocs", "tports"):
            self.action_detail()

    def action_admin(self):
        if is_admin():
            return
        if relaunch_as_admin():
            self.exit()
        else:
            self.notify("Elevation cancelled", severity="warning")

    def action_reset(self):
        with self.ledger.lock:
            self.ledger.pids.clear()
            self.ledger.flows.clear()
        self.pid_tot, self.flow_tot, self.port_prev = {}, {}, {}
        self.nic0 = psutil.net_io_counters()
        self.notify("Totals reset", timeout=1.5)


def _selftest():
    assert rates({1: (300, 100)}, {1: (100, 100)}, 2.0) == {1: (100.0, 0.0)}
    assert rates({2: (50, 5)}, {}, 1.0) == {2: (50.0, 5.0)}
    flows = {(9, "TCP", 443, "1.1.1.1", 5000): (10, 1), (9, "TCP", 443, "2.2.2.2", 6000): (5, 2), (8, "UDP", 53, "x", 1): (1, 1)}
    assert by_port(flows) == {("TCP", 443, 9): (15, 3), ("UDP", 53, 8): (1, 1)}
    assert fmt_bytes(512) == "512 B" and fmt_bytes(1536) == "1.5 K" and fmt_rate(0.5) == ""
    print("gotinfo selftest ok")


def main():
    if "--selftest" in sys.argv:
        import netetw
        netetw._selftest()
        _selftest()
        return
    GotInfo().run()


if __name__ == "__main__":
    main()
