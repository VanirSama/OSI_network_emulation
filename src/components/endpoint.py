from __future__ import annotations

from src.components.device import Device
from src.config import config
from src.proto.proto import NetworkPipeline, EthFrame, ARPPacket, IPPacket, UDPPacket
from src.utils.utils import bytes_to_ipv4, ipv4_to_bytes, mac_to_str, ipv4_to_str
from src.exceptions import EthFrameError, IPPacketError, ARPPacketError, UDPPacketError

import ipaddress


class Endpoint(Device):
    def __init__(self, name: str, gateway: str):
        super().__init__(name)
        self.gateway = gateway
        self.gateway_mac = None
        self.pending_data = []
        self.received_messages = []

    @property
    def gateway_mac(self) -> bytes | None:
        return self.arp_table.get(bytes_to_ipv4(ipv4_to_bytes(self.gateway)))

    @gateway_mac.setter
    def gateway_mac(self, mac: bytes | None):
        if mac is not None:
            self.arp_table[bytes_to_ipv4(ipv4_to_bytes(self.gateway))] = mac

    async def process_frame(self, iface: str, frame: bytes):
        try:
            self.logger.info(f"Processing {len(frame)}B frame at {iface}")
            eth = NetworkPipeline.decap_eth(frame)
            if eth.dst_mac != self.interfaces[iface].mac and eth.dst_mac != b'\xff\xff\xff\xff\xff\xff': return

            if eth.ethertype == 0x0806:  await self.handle_arp(eth.payload, iface)
            elif eth.ethertype == 0x0800: await self.handle_ip(eth.payload, iface)

        except (EthFrameError, IPPacketError, ARPPacketError, UDPPacketError) as e:
            self.logger.warning(f"Failed to process frame: {e}")

    async def handle_arp(self, arp_payload: bytes, iface: str):
        arp = NetworkPipeline.decap_arp(arp_payload)
        if arp.opcode == 1:
            target_ip_str = ipv4_to_str(arp.tgt_ip)
            my_ip_str = self.interfaces[iface].ip

            if target_ip_str == my_ip_str:
                sender_ip_str = ipv4_to_str(bytes_to_ipv4(arp.send_ip))
                if sender_ip_str == self.gateway:
                    self.gateway_mac = arp.send_mac
                    self.logger.info(f"Learned Gateway MAC: {mac_to_str(self.gateway_mac)})")

                reply_pkt = ARPPacket(
                    opcode=2,
                    send_mac=self.interfaces[iface].mac,
                    send_ip=ipv4_to_bytes(my_ip_str),
                    tgt_mac=arp.send_mac,
                    tgt_ip=arp.send_ip
                )
                reply_bytes = NetworkPipeline.encap_arp(reply_pkt)

                eth_frame = EthFrame(
                    src_mac=self.interfaces[iface].mac,
                    dst_mac=arp.send_mac,
                    ethertype=0x0806,
                    payload=reply_bytes
                )
                frame = NetworkPipeline.encap_eth(eth_frame)
                await self.send_frame(frame, iface)

        elif arp.opcode == 2:
            sender_ip_str = ipv4_to_str(bytes_to_ipv4(arp.send_ip))
            if sender_ip_str == self.gateway:
                self.gateway_mac = arp.send_mac
                self.logger.info(f"Gateway MAC resolved via ARP Reply: {mac_to_str(self.gateway_mac)}")
                await self.flush_pending_data(iface)

    async def handle_ip(self, ip_payload: bytes, iface: str):
        ip = NetworkPipeline.decap_ip(ip_payload)
        if ip.proto == 0x11:
            udp = NetworkPipeline.decap_udp(ip.payload)
            msg = udp.payload.decode('utf-8')
            src_ip_str = ipv4_to_str(ip.src_ip)
            self.logger.info(f"Received UDP msg: '{msg[:50]}{'...' if len(msg) > 50 else ""}' (total: {len(msg)}B) from {src_ip_str}:{udp.src_port}")
            self.received_messages.append(msg)

    async def send_udp_message(self, dst_ip: str, dst_port: int, msg: str):
        src_port = config.UDP_PORT
        payload = msg.encode('utf-8')

        udp_pkt = UDPPacket(src_port=src_port, dst_port=dst_port, payload=payload)
        udp_seg = NetworkPipeline.encap_udp(udp_pkt)

        ip_pkt_model = IPPacket(
            src_ip=ipv4_to_bytes(self.interfaces['eth0'].ip),
            dst_ip=ipv4_to_bytes(dst_ip),
            payload=udp_seg
        )
        ip_pkt = NetworkPipeline.encap_ip(ip_pkt_model)

        target_ip = dst_ip
        target_mac = None
        if ipaddress.ip_address(dst_ip) not in ipaddress.ip_network(f"{self.interfaces['eth0'].ip}/24", strict=False):
            target_ip = self.gateway
            target_mac = self.gateway_mac

        if target_mac:
            eth_frame = EthFrame(
                src_mac=self.interfaces['eth0'].mac,
                dst_mac=target_mac,
                ethertype=0x0800,
                payload=ip_pkt
            )
            frame = NetworkPipeline.encap_eth(eth_frame)
            await self.send_frame(frame, 'eth0')
        else:
            self.logger.info(f"No MAC for {target_ip}. Buffering message and sending ARP Request...")
            self.pending_data.append((dst_ip, dst_port, msg))

            arp_req_pkt = ARPPacket(
                opcode=1,
                send_mac=self.interfaces['eth0'].mac,
                send_ip=ipv4_to_bytes(self.interfaces['eth0'].ip),
                tgt_mac=b'\x00\x00\x00\x00\x00\x00',
                tgt_ip=ipv4_to_bytes(target_ip)
            )
            arp_req = NetworkPipeline.encap_arp(arp_req_pkt)

            eth_frame = EthFrame(
                src_mac=self.interfaces['eth0'].mac,
                dst_mac=b'\xff\xff\xff\xff\xff\xff',
                ethertype=0x0806,
                payload=arp_req
            )
            frame = NetworkPipeline.encap_eth(eth_frame)
            await self.send_frame(frame, 'eth0')

    async def flush_pending_data(self, iface: str):
        if not self.pending_data: return
        self.logger.info("Flushing buffered data...")
        for dst_ip, dst_port, msg in self.pending_data:
            await self.send_udp_message(dst_ip, dst_port, msg)
        self.pending_data.clear()
