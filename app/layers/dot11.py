from typing import Iterable, Tuple

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

    def extract_addresses(self) -> Tuple[str, str]:
        """
        Returns Client and Access Point MAC addresses.

        Client MAC may not make sense depending on packet: it's up to caller
        to use this function in correct scenarios (i.e. for beacons broadcast
        MAC will be returned as client)

        :return: (client, bssid)
        """
        assert not self.is_control(), "cannot extract bssid from control packets"

        if self.is_management():
            return self.addr1, self.addr3

        # Otherwise, its data packet
        from_ds = self.FCfield.from_DS
        to_ds = self.FCfield.to_DS

        # 802.11-2016 9.3.2.1: Table 9-26
        if from_ds and to_ds:
            return self.addr1, self.addr4
        if from_ds:
            return self.addr1, self.addr2
        if to_ds:
            return self.addr2, self.addr1

        return self.addr1, self.addr3
