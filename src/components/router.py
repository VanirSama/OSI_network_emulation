from __future__ import annotations

from src.components.device import Device
from src.proto.proto import NetworkPipeline, ARPPacket, EthFrame
from src.utils.utils import bytes_to_ipv4, ipv4_to_bytes, ipv4_to_str
from src.exceptions import EthFrameError, IPPacketError, ARPPacketError, UDPPacketError

import ipaddress


class Router(Device):
    def __init__(self, name: str):
        super().__init__(name)
        self.routes: dict[str, str] = {}

    def add_route(self, network: str, next_hop: str):
        self.routes[network] = next_hop

    def resolve_route(self, dst_ip: str) -> tuple[str | None, str]:
        ip_obj = ipaddress.ip_address(dst_ip)

        for iface_name, data in self.interfaces.items():
            if data.link and ip_obj in ipaddress.ip_network(f"{data.ip}/24", strict=False):
                return iface_name, dst_ip

        for net_str, next_hop in self.routes.items():
            if ip_obj in ipaddress.ip_network(net_str, strict=False):
                out_iface, _ = self.resolve_route(next_hop)
                return out_iface, next_hop

        return None, dst_ip
        

    async def process_frame(self, iface: str, frame: bytes):
        try:
            eth = NetworkPipeline.decap_eth(frame)
            if eth.ethertype == 0x0806: await self.handle_arp(eth.payload, iface)  # ARP
            elif eth.ethertype == 0x0800: await self.handle_ip(eth.payload, iface)  # IP
        except (EthFrameError, IPPacketError, ARPPacketError, UDPPacketError) as e: raise

    async def handle_arp(self, arp_payload: bytes, iface: str):
        arp = NetworkPipeline.decap_arp(arp_payload)

        sender_ip_int = bytes_to_ipv4(arp.send_ip)
        sender_mac = arp.send_mac

        self.learn_arp(arp.send_ip, arp.send_mac)

        if arp.opcode == 1:
            target_ip_int = bytes_to_ipv4(arp.tgt_ip)
            my_ip_str = self.interfaces[iface].ip
            my_ip_int = bytes_to_ipv4(ipv4_to_bytes(my_ip_str))

            if target_ip_int == my_ip_int:
                self.logger.info(f"ARP Request for {ipv4_to_str(target_ip_int)}. Sending Reply...")

                reply_pkt = ARPPacket(
                    opcode=2,
                    send_mac=self.interfaces[iface].mac,
                    send_ip=ipv4_to_bytes(my_ip_str),
                    tgt_mac=sender_mac,
                    tgt_ip=arp.send_ip
                )
                reply = NetworkPipeline.encap_arp(reply_pkt)

                eth_frame = EthFrame(
                    src_mac=self.interfaces[iface].mac,
                    dst_mac=sender_mac,
                    ethertype=0x0806,
                    payload=reply
                )
                frame = NetworkPipeline.encap_eth(eth_frame)
                await self.send_frame(frame, iface)

        elif arp.opcode == 2:
            await self.flush_pending_packets(sender_ip_int)

    async def handle_ip(self, ip_payload: bytes, in_iface: str):
        ip = NetworkPipeline.decap_ip(ip_payload)

        dst_ip_str = ipv4_to_str(ip.dst_ip)
        src_ip_str = ipv4_to_str(ip.src_ip)
        self.logger.info(f"Received IP packet from {src_ip_str} to {dst_ip_str}")

        out_iface, next_hop_str = self.resolve_route(dst_ip_str)
        if not out_iface:
            self.logger.warning(f"No route to {dst_ip_str}. Dropping.")
            return

        next_hop_int = bytes_to_ipv4(ipv4_to_bytes(next_hop_str))
        dst_mac = self.arp_table.get(next_hop_int)

        if dst_mac:
            await self.send_ip_frame(ip_payload, out_iface, dst_mac)
        else:
            self.pending_packets.setdefault(next_hop_int, []).append((ip_payload, out_iface))
            await self.send_arp_request(next_hop_str,out_iface)

    async def send_arp_request(self, target_ip: str, out_iface: str):
        my_mac = self.interfaces[out_iface].mac
        my_ip_str = self.interfaces[out_iface].ip

        arp_req_pkt = ARPPacket(
            opcode=1,
            send_mac=my_mac,
            send_ip=ipv4_to_bytes(my_ip_str),
            tgt_mac=b'\x00\x00\x00\x00\x00\x00',
            tgt_ip=ipv4_to_bytes(target_ip)
        )
        arp_req = NetworkPipeline.encap_arp(arp_req_pkt)

        eth_frame = EthFrame(
            src_mac=my_mac,
            dst_mac=b'\xff\xff\xff\xff\xff\xff',
            ethertype=0x0806,
            payload=arp_req
        )
        frame = NetworkPipeline.encap_eth(eth_frame)
        await self.send_frame(frame, out_iface)

    def find_out_iface(self, ip: str):
        for iface_name, data in self.interfaces.items():
            if data.link:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(f"{data.ip}/24", strict=False):
                    return iface_name
        return list(self.interfaces.keys())[0]
