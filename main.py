from __future__ import annotations

import asyncio
import argparse

from src.tests.topology import load_topology
from src.tests.scenario import ScenarioRunner


async def run_test(name: str):
    devices = load_topology(name)
    tasks = [asyncio.create_task(d.run()) for d in devices.values()]
    try: await ScenarioRunner(devices).run(name)
    finally:
        for d in devices.values(): d.running = False
        for t in tasks: t.cancel()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    args = parser.parse_args()
    asyncio.run(run_test(args.name))

if __name__ == "__main__":
    main()