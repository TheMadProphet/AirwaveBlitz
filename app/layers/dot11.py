from typing import Iterable

import scapy.layers.dot11 as dot11
from scapy.packet import Packet as ScapyPacket


class Packet(ScapyPacket):  # type: ignore
    @staticmethod
    def payloads(packet: ScapyPacket) -> Iterable[ScapyPacket]:
        payload = packet
        while payload:
            yield payload
            payload = payload.payload


class Dot11Extensions(dot11.Dot11):  # type: ignore
    MANAGEMENT = 0
    CONTROL = 1
    DATA = 2

    @staticmethod
    def patch() -> None:
        dot11.Dot11.is_management = Dot11Extensions.is_management
        dot11.Dot11.is_control = Dot11Extensions.is_control
        dot11.Dot11.is_data = Dot11Extensions.is_data
        dot11.Dot11.extract_addresses = Dot11Extensions.extract_addresses

    def is_management(self) -> bool:
        return self.type == Dot11Extensions.MANAGEMENT

    def is_control(self) -> bool:
        return self.type == Dot11Extensions.CONTROL

    def is_data(self) -> bool:
        return self.type == Dot11Extensions.DATA
