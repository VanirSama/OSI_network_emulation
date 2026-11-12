from __future__ import annotations

from src.proto.proto import NetworkPipeline, EthFrame, ARPPacket
from src.utils.utils import mac_to_bytes, bytes_to_ipv4, ipv4_to_bytes, mac_to_str, ipv4_to_str
from src.utils.logs import LoggerFactory

from asyncio import Queue, create_task
from dataclasses import dataclass


BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'
ZERO_MAC      = b'\x00\x00\x00\x00\x00\x00'


@dataclass
class NetworkInterface:
    ip: str
    mac: bytes
    link: tuple[Device, str] | None = None

    def __str__(self):
        return f"(IP: {self.ip} MAC: {mac_to_str(self.mac)})"


class Device:
    def __init__(self, name: str):
        self.name = name
        self.logger = LoggerFactory.new_logger(name=self.name)
        self.interfaces: dict[str, NetworkInterface] = {}
        self.inbox = Queue()
        self.running = False
        self.arp_table: dict[int, bytes] = {}
        self.pending_packets: dict[int, list[tuple[bytes, str]]] = {}

        self.logger.info("Initialized device")

    def __del__(self):
        LoggerFactory.del_logger(self.name)

    def add_interface(self, iface: str, ip: str, mac: str):
        self.interfaces[iface] = NetworkInterface(ip=ip, mac=mac_to_bytes(mac))

        self.logger.info(f"Added new interface {iface}: {self.interfaces[iface]}")

    def connect(self, my_iface: str, other_device: Device, other_iface: str):
        self.interfaces[my_iface].link = (other_device, other_iface)
        other_device.interfaces[other_iface].link = (self, my_iface)

        self.logger.info(f"Linked device {other_device.name}:{other_iface} to {self.name}:{my_iface}")

    async def send_frame(self, frame: bytes, out_iface: str):
        link = self.interfaces[out_iface].link
        if link:
            target_dev, target_iface = link
            await target_dev.inbox.put((target_iface, frame))
            self.logger.info(f"Sending {len(frame)} B frame at {out_iface}")

    async def send_ip_frame(self, ip_payload: bytes, out_iface: str, dst_mac: bytes):
        eth_frame = EthFrame(src_mac=self.interfaces[out_iface].mac, dst_mac=dst_mac, ethertype=0x0800, payload=ip_payload)
        await self.send_frame(NetworkPipeline.encap_eth(eth_frame), out_iface)

        self.logger.info(f"Sent {len(ip_payload)} B IP packet on {out_iface} to {mac_to_str(dst_mac)}")

    async def send_arp_request(self, iface: str, target_ip: str):
        my = self.interfaces[iface]
        arp = ARPPacket(opcode=1, send_mac=my.mac, send_ip=ipv4_to_bytes(my.ip), tgt_mac=ZERO_MAC, tgt_ip=ipv4_to_bytes(target_ip))
        eth_frame = EthFrame(src_mac=my.mac, dst_mac=BROADCAST_MAC, ethertype=0x0806, payload=NetworkPipeline.encap_arp(arp))
        await self.send_frame(NetworkPipeline.encap_eth(eth_frame), iface)

        self.logger.info(f"Sent ARP request to resolve {target_ip}")

    async def send_arp_reply(self, iface: str, claim_ip: str, tgt_ip: str, tgt_mac: bytes, send_mac: bytes | None = None):
        my = self.interfaces[iface]
        arp = ARPPacket(opcode=2, send_mac=send_mac or my.mac, send_ip=ipv4_to_bytes(claim_ip), tgt_mac=tgt_mac, tgt_ip=ipv4_to_bytes(tgt_ip))
        eth_frame = EthFrame(src_mac=my.mac, dst_mac=tgt_mac, ethertype=0x0806, payload=NetworkPipeline.encap_arp(arp))
        await self.send_frame(NetworkPipeline.encap_eth(eth_frame), iface)

        self.logger.info(f"Sent ARP response resolving {claim_ip} to (IP: {tgt_ip} MAC: {mac_to_str(tgt_mac)}). Resolved_MAC={mac_to_str(send_mac)}")

    def learn_arp(self, ip_bytes: bytes, mac: bytes):
        self.arp_table[bytes_to_ipv4(ip_bytes)] = mac

        self.logger.info(f"ARP table updated: {ipv4_to_str(ip_bytes)} -> {mac_to_str(mac)}")

    async def flush_pending_packets(self, ip_int: int):
        dst_mac = self.arp_table.get(ip_int)
        for ip_payload, out_iface in self.pending_packets.get(ip_int, []):
            if dst_mac:
                await self.send_ip_frame(ip_payload, out_iface, dst_mac)
        self.pending_packets.pop(ip_int, None)

    async def run(self):
        self.running = True
        self.logger.info("Device running")
        while self.running:
            iface, frame = await self.inbox.get()
            create_task(self.process_frame(iface, frame))

    async def process_frame(self, iface: str, frame: bytes):
        raise NotImplementedError
