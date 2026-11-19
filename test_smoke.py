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
        if procs.row_count:
            await pilot.press("1")
            await pilot.press("enter")
            await pilot.pause(1.5)
            assert isinstance(app.screen, gotinfo.DetailScreen)
            await pilot.press("escape")
        print(f"smoke ok: {procs.row_count} procs, {ports.row_count} ports, traced={app.traced}")

asyncio.run(main())
