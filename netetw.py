"""Per-process network accounting via ETW (Microsoft-Windows-Kernel-Network).

Real-time trace session, pure ctypes, no extra deps. Needs admin.
Covers TCP + UDP (so QUIC too), v4 + v6, including short-lived connections.

Run directly (elevated) for a 10s spike:  python netetw.py
"""
from __future__ import annotations

import ctypes
import socket
import struct
import threading
import time
from ctypes import POINTER, Structure, Union, byref, c_int64, c_long, c_ubyte, c_uint64, c_ulong, c_ushort, c_void_p, c_wchar, c_wchar_p, sizeof
from dataclasses import dataclass, field

SESSION_NAME = "GotInfoLocalNet"

# ── Win32 structures ─────────────────────────────────────────────────────────


class GUID(Structure):
    _fields_ = [("Data1", c_ulong), ("Data2", c_ushort), ("Data3", c_ushort), ("Data4", c_ubyte * 8)]

    @classmethod
    def parse(cls, s: str) -> "GUID":
        import uuid
        u = uuid.UUID(s)
        g = cls()
        g.Data1, g.Data2, g.Data3 = u.fields[0], u.fields[1], u.fields[2]
        g.Data4[:] = list(u.bytes[8:])
        return g


KERNEL_NETWORK = "{7DD42A49-5329-4832-8DFD-43D979153A88}"


class WNODE_HEADER(Structure):
    _fields_ = [("BufferSize", c_ulong), ("ProviderId", c_ulong), ("HistoricalContext", c_uint64),
                ("TimeStamp", c_int64), ("Guid", GUID), ("ClientContext", c_ulong), ("Flags", c_ulong)]


class EVENT_TRACE_PROPERTIES(Structure):
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", c_ulong), ("MinimumBuffers", c_ulong),
                ("MaximumBuffers", c_ulong), ("MaximumFileSize", c_ulong), ("LogFileMode", c_ulong),
                ("FlushTimer", c_ulong), ("EnableFlags", c_ulong), ("AgeLimit", c_long),
                ("NumberOfBuffers", c_ulong), ("FreeBuffers", c_ulong), ("EventsLost", c_ulong),
                ("BuffersWritten", c_ulong), ("LogBuffersLost", c_ulong), ("RealTimeBuffersLost", c_ulong),
                ("LoggerThreadId", c_void_p), ("LogFileNameOffset", c_ulong), ("LoggerNameOffset", c_ulong)]


class EVENT_DESCRIPTOR(Structure):
    _fields_ = [("Id", c_ushort), ("Version", c_ubyte), ("Channel", c_ubyte), ("Level", c_ubyte),
                ("Opcode", c_ubyte), ("Task", c_ushort), ("Keyword", c_uint64)]


class EVENT_HEADER(Structure):
    _fields_ = [("Size", c_ushort), ("HeaderType", c_ushort), ("Flags", c_ushort), ("EventProperty", c_ushort),
                ("ThreadId", c_ulong), ("ProcessId", c_ulong), ("TimeStamp", c_int64), ("ProviderId", GUID),
                ("EventDescriptor", EVENT_DESCRIPTOR), ("ProcessorTime", c_uint64), ("ActivityId", GUID)]


class EVENT_RECORD(Structure):
    _fields_ = [("EventHeader", EVENT_HEADER), ("BufferContext", c_ulong), ("ExtendedDataCount", c_ushort),
                ("UserDataLength", c_ushort), ("ExtendedData", c_void_p), ("UserData", c_void_p),
                ("UserContext", c_void_p)]


class EVENT_TRACE_HEADER(Structure):
    _fields_ = [("Size", c_ushort), ("FieldTypeFlags", c_ushort), ("Version", c_ulong), ("ThreadId", c_ulong),
                ("ProcessId", c_ulong), ("TimeStamp", c_int64), ("Guid", GUID), ("ProcessorTime", c_uint64)]


class EVENT_TRACE(Structure):
    _fields_ = [("Header", EVENT_TRACE_HEADER), ("InstanceId", c_ulong), ("ParentInstanceId", c_ulong),
                ("ParentGuid", GUID), ("MofData", c_void_p), ("MofLength", c_ulong), ("ClientContext", c_ulong)]


class SYSTEMTIME(Structure):
    _fields_ = [(n, c_ushort) for n in ("wYear", "wMonth", "wDayOfWeek", "wDay", "wHour", "wMinute", "wSecond", "wMilliseconds")]


class TIME_ZONE_INFORMATION(Structure):
    _fields_ = [("Bias", c_long), ("StandardName", c_wchar * 32), ("StandardDate", SYSTEMTIME), ("StandardBias", c_long),
                ("DaylightName", c_wchar * 32), ("DaylightDate", SYSTEMTIME), ("DaylightBias", c_long)]


class TRACE_LOGFILE_HEADER(Structure):
    _fields_ = [("BufferSize", c_ulong), ("Version", c_ulong), ("ProviderVersion", c_ulong),
                ("NumberOfProcessors", c_ulong), ("EndTime", c_int64), ("TimerResolution", c_ulong),
                ("MaximumFileSize", c_ulong), ("LogFileMode", c_ulong), ("BuffersWritten", c_ulong),
                ("LogInstanceGuid", GUID), ("LoggerName", c_wchar_p), ("LogFileName", c_wchar_p),
                ("TimeZone", TIME_ZONE_INFORMATION), ("BootTime", c_int64), ("PerfFreq", c_int64),
                ("StartTime", c_int64), ("ReservedFlags", c_ulong), ("BuffersLost", c_ulong)]


EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, POINTER(EVENT_RECORD))
BUFFER_CALLBACK = ctypes.WINFUNCTYPE(c_ulong, c_void_p)


class EVENT_TRACE_LOGFILEW(Structure):
    _fields_ = [("LogFileName", c_wchar_p), ("LoggerName", c_wchar_p), ("CurrentTime", c_int64),
                ("BuffersRead", c_ulong), ("ProcessTraceMode", c_ulong), ("CurrentEvent", EVENT_TRACE),
                ("LogfileHeader", TRACE_LOGFILE_HEADER), ("BufferCallback", BUFFER_CALLBACK),
                ("BufferSize", c_ulong), ("Filled", c_ulong), ("EventsLost", c_ulong),
                ("EventRecordCallback", EVENT_RECORD_CALLBACK), ("IsKernelTrace", c_ulong), ("Context", c_void_p)]


assert sizeof(EVENT_TRACE) == 88 and sizeof(TRACE_LOGFILE_HEADER) == 280, "ETW struct layout (x64 only)"

WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
EVENT_TRACE_CONTROL_STOP = 1
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
INVALID_TRACEHANDLE = 0xFFFFFFFFFFFFFFFF
ERROR_ALREADY_EXISTS = 183

# ── Payload parsing ──────────────────────────────────────────────────────────
# Kernel-Network send/recv events: PID u32, size u32, daddr, saddr, dport u16be, sport u16be, ...
# TCP (both directions) and UDP send: daddr/dport = remote, saddr/sport = local. UDP recv: reversed.
#             id: (proto, ipv6, is_send)
EVENTS = {10: ("TCP", False, True), 11: ("TCP", False, False),
          26: ("TCP", True, True), 27: ("TCP", True, False),
          42: ("UDP", False, True), 43: ("UDP", False, False),
          58: ("UDP", True, True), 59: ("UDP", True, False)}


def parse(event_id: int, data: bytes):
    """-> (pid, size, proto, is_send, laddr, lport, raddr, rport) or None."""
    kind = EVENTS.get(event_id)
    if not kind:
        return None
    proto, v6, is_send = kind
    alen = 16 if v6 else 4
    need = 8 + 2 * alen + 4
    if len(data) < need:
        return None
    pid, size = struct.unpack_from("<II", data, 0)
    fam = socket.AF_INET6 if v6 else socket.AF_INET
    raddr = socket.inet_ntop(fam, data[8:8 + alen])
    laddr = socket.inet_ntop(fam, data[8 + alen:8 + 2 * alen])
    rport, lport = struct.unpack_from(">HH", data, 8 + 2 * alen)
    if proto == "UDP" and not is_send:  # UDP recv is packet-literal: d* = local, s* = remote (seen live)
        laddr, lport, raddr, rport = raddr, rport, laddr, lport
    return pid, size, proto, is_send, laddr, lport, raddr, rport


# ── Ledger (accounting, thread-safe) ─────────────────────────────────────────

@dataclass
class Counter:
    rx: int = 0
    tx: int = 0


@dataclass
class Ledger:
    """Byte totals since launch: per pid, and per flow (pid, proto, lport, raddr, rport)."""
    pids: dict = field(default_factory=dict)
    flows: dict = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)  # ponytail: one global lock; fine at Python callback rates

    def add(self, pid, size, proto, is_send, laddr, lport, raddr, rport):
        with self.lock:
            for d, k in ((self.pids, pid), (self.flows, (pid, proto, lport, raddr, rport))):
                c = d.get(k)
                if c is None:
                    c = d[k] = Counter()
                if is_send:
                    c.tx += size
                else:
                    c.rx += size

    def snapshot(self):
        """-> ({pid: (rx, tx)}, {flow: (rx, tx)}) copies safe to read without the lock."""
        with self.lock:
            return ({k: (c.rx, c.tx) for k, c in self.pids.items()},
                    {k: (c.rx, c.tx) for k, c in self.flows.items()})


# ── Trace session ────────────────────────────────────────────────────────────

def _props():
    size = sizeof(EVENT_TRACE_PROPERTIES) + 1024
    buf = ctypes.create_string_buffer(size)
    p = ctypes.cast(buf, POINTER(EVENT_TRACE_PROPERTIES)).contents
    p.Wnode.BufferSize = size
    p.Wnode.Flags = WNODE_FLAG_TRACED_GUID
    p.Wnode.ClientContext = 1  # QPC timestamps
    p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
    p.FlushTimer = 1
    p.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES)
    return buf, p


class NetTrace:
    """Start/stop a real-time Kernel-Network ETW session feeding a Ledger."""

    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self.error: str | None = None
        self.events = 0
        self._session = c_uint64(0)
        self._consumer = c_uint64(INVALID_TRACEHANDLE)
        self._thread = None
        self._cb = EVENT_RECORD_CALLBACK(self._on_event)  # keep a reference or ctypes frees it

    def _on_event(self, rec):
        r = rec.contents
        n = r.UserDataLength
        if not n or not r.UserData:
            return
        p = parse(r.EventHeader.EventDescriptor.Id, ctypes.string_at(r.UserData, n))
        if p:
            self.events += 1
            self.ledger.add(*p)

    @staticmethod
    def stop_stale():
        buf, p = _props()
        ctypes.windll.advapi32.ControlTraceW(c_uint64(0), SESSION_NAME, byref(p), EVENT_TRACE_CONTROL_STOP)

    def start(self) -> bool:
        adv = ctypes.windll.advapi32
        adv.EnableTraceEx2.argtypes = [c_uint64, POINTER(GUID), c_ulong, c_ubyte, c_uint64, c_uint64, c_ulong, c_void_p]
        adv.OpenTraceW.restype = c_uint64
        buf, p = _props()
        rc = adv.StartTraceW(byref(self._session), SESSION_NAME, byref(p))
        if rc == ERROR_ALREADY_EXISTS:  # left over from a crashed run
            self.stop_stale()
            buf, p = _props()
            rc = adv.StartTraceW(byref(self._session), SESSION_NAME, byref(p))
        if rc:
            self.error = f"StartTrace failed ({rc}{' — run as admin' if rc == 5 else ''})"
            return False
        guid = GUID.parse(KERNEL_NETWORK)
        rc = adv.EnableTraceEx2(self._session.value, byref(guid), 1, 5, 0x30, 0, 0, None)  # keywords IPv4|IPv6
        if rc:
            self.error = f"EnableTraceEx2 failed ({rc})"
            self.stop()
            return False
        lf = EVENT_TRACE_LOGFILEW()
        lf.LoggerName = SESSION_NAME
        lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        lf.EventRecordCallback = self._cb
        self._lf = lf
        self._consumer = c_uint64(adv.OpenTraceW(byref(lf)))
        if self._consumer.value == INVALID_TRACEHANDLE:
            self.error = f"OpenTrace failed ({ctypes.GetLastError()})"
            self.stop()
            return False
        self._thread = threading.Thread(target=lambda: adv.ProcessTrace(byref(self._consumer), 1, None, None), daemon=True)
        self._thread.start()
        return True

    def stop(self):
        adv = ctypes.windll.advapi32
        if self._consumer.value != INVALID_TRACEHANDLE:
            adv.CloseTrace(self._consumer)
            self._consumer = c_uint64(INVALID_TRACEHANDLE)
        self.stop_stale()


def _selftest():
    ip4 = lambda s: socket.inet_aton(s)
    blob = struct.pack("<II", 1234, 1500) + ip4("1.2.3.4") + ip4("10.0.0.5") + struct.pack(">HH", 443, 50000) + b"\0" * 16
    assert parse(11, blob) == (1234, 1500, "TCP", False, "10.0.0.5", 50000, "1.2.3.4", 443)
    assert parse(42, blob)[2:4] == ("UDP", True)
    assert parse(12, blob) is None and parse(10, blob[:10]) is None
    v6 = struct.pack("<II", 7, 99) + socket.inet_pton(socket.AF_INET6, "::1") * 2 + struct.pack(">HH", 53, 6000)
    assert parse(59, v6) == (7, 99, "UDP", False, "::1", 53, "::1", 6000)  # UDP recv swaps sides
    assert parse(43, blob)[4:] == ("1.2.3.4", 443, "10.0.0.5", 50000)
    led = Ledger()
    led.add(*parse(11, blob))
    led.add(*parse(10, blob))
    led.add(*parse(10, blob))
    pids, flows = led.snapshot()
    assert pids == {1234: (1500, 3000)}
    assert flows == {(1234, "TCP", 50000, "1.2.3.4", 443): (1500, 3000)}
    print("netetw selftest ok")


if __name__ == "__main__":
    _selftest()
    led = Ledger()
    t = NetTrace(led)
    if not t.start():
        raise SystemExit(t.error)
    try:
        time.sleep(10)
    finally:
        t.stop()
    pids, flows = led.snapshot()
    print(f"{t.events} events")
    for pid, (rx, tx) in sorted(pids.items(), key=lambda kv: -sum(kv[1]))[:15]:
        print(f"pid {pid:>6}  rx {rx:>12,}  tx {tx:>12,}")
    for f, (rx, tx) in sorted(flows.items(), key=lambda kv: -sum(kv[1]))[:10]:
        print(f, rx, tx)
