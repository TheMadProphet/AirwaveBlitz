from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set

from scapy.layers.dot11 import (
    AKMSuite,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltMicrosoftWPA,
    Dot11ProbeResp,
    RadioTap,
    RSNCipherSuite,
)
from scapy.layers.eap import EAPOL
from scapy.plist import PacketList

from app.packets.dot11 import Dot11EltDSSSet, Dot11EltRSN, Dot11EltSSID, Packet


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    security: Set[str]
    signal: int
    channel: int
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


@dataclass
class Device:
    mac: str
    bssid: str
    signal: int  # ?


@dataclass
class Handshake:
    bssid: str
    keys: Dict[int, EAPOL]

    def is_captured(self) -> bool:
        return self.keys is not None


class Statistics:
    def __init__(self) -> None:
        self.access_points: Dict[str, AccessPoint] = dict()
        self.handshakes: Dict[str, Handshake] = dict()
        self.devices: Dict[str, Device] = dict()
        self.packets = PacketList()

    def process_packet(self, packet: Packet) -> None:
        if packet.haslayer(Dot11):
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                self.__process_beacon_manual(packet)

        self.packets.append(packet)

    def get_ap(self, mac: str) -> AccessPoint:
        return self.access_points[mac]

    def __process_beacon_manual(self, packet: Packet) -> None:
        assert packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)

        ap = AccessPoint.empty(bssid=packet[Dot11].addr3)
        for elt in Packet.payloads(packet):
            if not isinstance(elt, Dot11Elt):
                continue

            if isinstance(elt, Dot11EltSSID):
                ap.ssid = elt.value()

            if isinstance(elt, Dot11EltDSSSet):
                ap.channel = elt.value()

            if isinstance(elt, Dot11EltRSN):
                ap.security.add(elt.value())

            if isinstance(elt, Dot11EltMicrosoftWPA):
                if elt.akm_suites:
                    auth = elt.akm_suites[0].sprintf("%suite%")
                    ap.security.add("WPA/%s" % auth)
                else:
                    ap.security.add("WPA")

        if not ap.security and hasattr(packet, "cap"):
            if packet.cap.privacy:
                ap.security.add("WEP")
            else:
                ap.security.add("OPN")

        if ap.bssid in self.access_points:
            old_ap = self.access_points[ap.bssid]
            ap.beacon_count = old_ap.beacon_count + 1
        elif packet.haslayer(Dot11Beacon):
            ap.beacon_count += 1

        self.access_points[ap.bssid] = ap
