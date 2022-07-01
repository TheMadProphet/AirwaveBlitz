from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Set

from scapy.layers.dot11 import AKMSuite, Dot11, Dot11Beacon, RadioTap, RSNCipherSuite

from app.entities.device import Device
from app.entities.handshake import Handshake
from app.layers.dot11 import Dot11Extensions, Packet
from app.layers.elt import Dot11EltDSSSet, Dot11EltRSN, Dot11EltSSID

Dot11Extensions.patch()


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    security: Set[str]
    signal: int
    channel: int
    devices: Set[Device] = field(default_factory=set)
    handshake: Optional[Handshake] = None
    beacon_count: int = 0
    data_transferred: int = 0

    @staticmethod
    def empty(ssid: str = "", bssid: str = "") -> AccessPoint:
        return AccessPoint(ssid=ssid, bssid=bssid, security=set(), signal=0, channel=0)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AccessPoint) and self.bssid == other.bssid

    def forge_beacon(self) -> Packet:
        # TODO: create management/beacon layers
        return (
            RadioTap()
            / Dot11(
                type=0,  # management
                subtype=8,  # beacon
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self.bssid,
                addr3=self.bssid,
            )
            / Dot11Beacon(cap="ESS+privacy")
            / Dot11EltSSID(ssid=str.encode(self.ssid), len=len(self.ssid))
            / Dot11EltDSSSet(channel=self.channel)
            / Dot11EltRSN(
                group_cipher_suite=RSNCipherSuite(cipher=0x2),
                pairwise_cipher_suites=[RSNCipherSuite(cipher=0x2)],
                akm_suites=[AKMSuite(suite=0x2)],
            )
        )
