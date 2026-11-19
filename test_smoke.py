"""Headless smoke test: app boots, both tables fill, tab switch + detail open work. Run: python test_smoke.py"""
import asyncio
import gotinfo


async def main():
    gotinfo._selftest()
    app = gotinfo.GotInfo()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause(2.5)
        procs = app.query_one("#tprocs")
        ports = app.query_one("#tports")
        assert ports.row_count > 0, "no open ports listed"
        await pilot.press("2")
        await pilot.press("s")
        await pilot.press("c")
        await pilot.pause(0.3)
        assert all(ports.get_row_at(i)[2] != "closed" for i in range(ports.row_count))
        await pilot.press("c")
        depth = len(app.screen_stack)
        for open_key in ("1", "2"):  # detail opens from both tabs
            await pilot.press(open_key)
            await pilot.press("enter")
            await pilot.pause(1.5)
            assert isinstance(app.screen, gotinfo.DetailScreen), open_key
            await pilot.press("enter")  # Enter on a flow row must close, not stack another detail
            await pilot.pause(0.3)
            assert len(app.screen_stack) == depth, (open_key, len(app.screen_stack))
        print(f"smoke ok: {procs.row_count} procs, {ports.row_count} ports, traced={app.traced}")

asyncio.run(main())
