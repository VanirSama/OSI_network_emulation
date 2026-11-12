from src.components.device import Device
from src.proto.proto import NetworkPipeline
from src.exceptions import EthFrameError


class Switch(Device):
    def __init__(self, name: str):
        super().__init__(name)
        self.mac_table: dict[bytes, str] = {}

    async def process_frame(self, iface: str, frame: bytes):
        try: eth = NetworkPipeline.decap_eth(frame)
        except EthFrameError as e:
            self.logger.warning(f"Dropped malformed frame: {e}")
            return

        self.mac_table[eth.src_mac] = iface

        if eth.dst_mac in self.mac_table:
            out = self.mac_table[eth.dst_mac]
            if out != iface:
                await self.send_frame(frame, out)
            return

        for port in self.interfaces:
            if port != iface:
                await self.send_frame(frame, port)
