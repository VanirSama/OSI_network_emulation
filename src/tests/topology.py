from __future__ import annotations

from pathlib import Path
import yaml

from src.components.device import Device
from src.components.endpoint import Endpoint
from src.components.router import Router
from src.components.switch import Switch
from src.components.spoofer import Spoofer


DEVICE_TYPES: dict[str, type[Device]] = {
    "Endpoint": Endpoint,
    "Router":   Router,
    "Switch":   Switch,
    "Spoofer":  Spoofer,
}

def load_topology(name: str) -> dict[str, Device]:
    path = Path(__file__).parent.parent.parent / "fixtures" / f"{name}_topology.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    devices: dict[str, Device] = {}

    for spec in data["devices"]:
        cls = DEVICE_TYPES[spec["type"]]
        dev = cls(name=spec["name"], **spec.get("params", {}))

        for i in spec.get("interfaces", []):
            dev.add_interface(i["iface"], i["ip"], i["mac"])

        if isinstance(dev, Router):
            for r in spec.get("routes", []):
                dev.add_route(r["network"], r["next_hop"])

        devices[spec["id"]] = dev

    for link in data.get("links", []):
        a, b = link["a"], link["b"]
        dev_a, dev_b = devices[a["dev"]], devices[b["dev"]]
        if dev_a is dev_b:
            raise ValueError(f"Self-loop link on {a['dev']}:{a['iface']}")
        dev_a.connect(a["iface"], dev_b, b["iface"])

    return devices