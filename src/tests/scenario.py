from __future__ import annotations

import asyncio, time
from pathlib import Path
from typing import Any, Callable

import yaml

from src.components.device import Device


async def wait_until(pred: Callable[[], bool], timeout: float, interval: float = 0.05):
    deadline = time.monotonic() + timeout
    while not pred():
        if time.monotonic() > deadline:
            raise TimeoutError(f"Condition not met within {timeout}s")
        await asyncio.sleep(interval)


class ScenarioRunner:
    def __init__(self, devices: dict[str, Device]):
        self.devices = devices

    def _ns(self) -> dict[str, Any]:
        from src.utils.utils import bytes_to_ipv4, ipv4_to_bytes
        return {
            "devices": self.devices,
            **self.devices,
            "len": len, "any": any, "all": all,
            "bytes_to_ipv4": bytes_to_ipv4,
            "ipv4_to_bytes": ipv4_to_bytes,
        }

    def _eval(self, expr: str) -> Any:
        return eval(expr, {"__builtins__": {}}, self._ns())

    async def run(self, name: str):
        path = Path(__file__).parent.parent.parent / "fixtures" / f"{name}_scenario.yaml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for step in data["steps"]:
            (kind, args), = step.items()
            await self._run_step(kind, args)

    async def _run_step(self, kind: str, args: Any):
        if kind == "sleep":  await asyncio.sleep(float(args))
        elif kind == "wait":
            await wait_until(
                lambda: self._eval(args["until"]),
                timeout=args.get("timeout", 3.0),
                interval=args.get("interval", 0.05),
            )
        elif kind == "send_udp": await self.devices[args["dev"]].send_udp_message(args["dst_ip"], args["dst_port"], args["msg"])
        elif kind == "start_spoofer": await self.devices[args["dev"]].start()
        elif kind == "stop_spoofer": await self.devices[args["dev"]].stop()
        elif kind == "assert":
            if not self._eval(args["expr"]): raise AssertionError(args.get("message", args["expr"]))
        else: raise ValueError(f"Unknown scenario step: {kind}")