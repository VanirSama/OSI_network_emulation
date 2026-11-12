from ipaddress import IPv4Address
from typing import overload
import socket


class SingletonMeta(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)

        return cls._instances[cls]


@overload
def ipv4_to_bytes(ip: int) -> bytes: ...

@overload
def ipv4_to_bytes(ip: IPv4Address) -> bytes: ...

@overload
def ipv4_to_bytes(ip: str) -> bytes: ...

def ipv4_to_bytes(ip: int | IPv4Address | str) -> bytes:
    if isinstance(ip, str): return socket.inet_aton(ip)
    elif isinstance(ip, IPv4Address): return int(ip).to_bytes(4, byteorder="big")
    elif isinstance(ip, int): return ip.to_bytes(4, byteorder="big")
    else: raise TypeError(f"Unsupportable parameter type for function \"ip_to_bytes\": int|IPv4Address|str. Received parameter with type \"{type(ip).__name__}\".")

@overload
def mac_to_bytes(mac: int) -> bytes: ...

@overload
def mac_to_bytes(mac: str) -> bytes: ...

def mac_to_bytes(mac: str | int) -> bytes:
    if isinstance(mac, str):
        hextets = mac.split(":")
        if (l:=len(hextets)) != 6: raise ValueError(f"Invalid MAC address format. Number of MAC-address hextets must be 6, not {l}.")
        return bytes(int(x, 16) for x in hextets)

    elif isinstance(mac, int):
        if mac < 0x0 or mac > 0xFFFFFFFFFFFF: raise ValueError(f"Given value {mac} for MAC-address is out of range of valid MAC-address values.")
        return mac.to_bytes(6, byteorder="big")

    else: raise TypeError(f"Unsupportable parameter type for function \"mac_to_bytes\": int|str. Received parameter with type \"{type(mac).__name__}\".")

def bytes_to_ipv4(b: bytes) -> int: return int.from_bytes(b, byteorder="big")

def bytes_to_mac(b: bytes) -> int: return int.from_bytes(b, byteorder="big")

def mac_to_str(mac: int | bytes | None = None) -> str:
    if mac is None: return "??:??:??:??:??:??"
    if isinstance(mac, bytes): mac = bytes_to_mac(mac)
    if mac < 0x0 or mac > 0xFFFFFFFFFFFF: return "XX:XX:XX:XX:XX:XX"

    hex_str = f"{mac:012x}".upper()
    return ":".join(hex_str[i:i + 2] for i in range(0, 12, 2))

def ipv4_to_str(ip: int | IPv4Address | bytes) -> str: return str(IPv4Address(ip))