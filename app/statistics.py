from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

from scapy.layers.dot11 import (
    AKMSuite,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltMicrosoftWPA,
    Dot11FCS,
    Dot11ProbeResp,
    RadioTap,
    RSNCipherSuite,
)
from scapy.plist import PacketList

from app.layers.dot11 import Packet
from app.layers.eap import EAPOLKey
from app.layers.elt import Dot11EltDSSSet, Dot11EltRSN, Dot11EltSSID


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
    messages: Dict[int, Packet]

    def register_message(self, packet: Packet) -> None:
        if self.is_captured():
            return

        key = packet[EAPOLKey]
        key_number = key.guess_key_number()

        if key_number == 1:
            self.reset()
            self.messages[key_number] = packet

        elif key_number == 2:
            self.messages[key_number] = packet

        elif key_number == 3:
            if key.nonce == self.messages[1].nonce:
                self.messages[key_number] = packet

        elif key_number == 4:
            if key.nonce == self.messages[2].nonce:
                self.messages[key_number] = packet

    def is_captured(self) -> bool:
        if len(self.messages) == 4:
            return (
                self.messages[1].nonce == self.messages[3].nonce
                and self.messages[2].nonce == self.messages[4].nonce
            )

        return False

    def reset(self) -> None:
        self.messages = dict()

    def packets(self) -> PacketList:
        return PacketList(list(self.messages.values()))


class Statistics:
    def __init__(self) -> None:
        self.access_points: Dict[str, AccessPoint] = dict()
        self.handshakes: Dict[Tuple[str, str], Handshake] = dict()
        self.devices: Dict[str, Device] = dict()
        self.packets = PacketList()

    def process_packet(self, packet: Packet) -> None:
        if Dot11 in packet:
            if packet[Dot11].is_data():
                self.__process_data(packet)
            if Dot11Beacon in packet or Dot11ProbeResp in packet:
                self.__process_beacon(packet)
            if EAPOLKey in packet:
                self.__process_eapol_key(packet)

        self.packets.append(packet)

    def get_ap(self, mac: str) -> AccessPoint:
        return self.access_points[mac]

    def get_handshake(self, bssid: str) -> Optional[PacketList]:
        for (_bssid, client), handshake in self.handshakes.items():
            if _bssid == bssid and handshake.is_captured():
                return handshake.packets()

        return None

    def __process_data(self, packet: Packet) -> None:
        assert Dot11 in packet and packet[Dot11].is_data()
        # TODO: Data frames in sample.pcap, add bssid->devices
        pass

    def __process_beacon(self, packet: Packet) -> None:
        assert Dot11Beacon in packet or Dot11ProbeResp in packet

        ap = AccessPoint.empty(bssid=packet[Dot11].addr3)
        # TODO: iterpayloads
        for elt in Packet.payloads(packet):
            if not isinstance(elt, Dot11Elt):
                continue

            if isinstance(elt, Dot11EltSSID):
                ap.ssid = elt.get_ssid()

            if isinstance(elt, Dot11EltDSSSet):
                ap.channel = elt.channel

            if isinstance(elt, Dot11EltRSN):
                ap.security.add(elt.get_security())

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
        elif Dot11Beacon in packet:
            ap.beacon_count += 1

        self.access_points[ap.bssid] = ap

    def __process_eapol_key(self, packet: Packet) -> None:
        assert EAPOLKey in packet

        bssid, client = self.__extract_macs_from(packet)
        if (bssid, client) in self.handshakes:
            handshake = self.handshakes[bssid, client]
        else:
            handshake = Handshake(dict())

        handshake.register_message(packet)

        if handshake.is_captured():
            # TODO: consider returning event when processing packet
            print("Captured entire handshake!")

        self.handshakes[bssid, client] = handshake

    @staticmethod
    def __extract_macs_from(packet: Packet) -> Tuple[str, str]:
        if Dot11FCS in packet:
            fcs = packet[Dot11FCS]
            bssid = fcs.addr3
            client = fcs.addr1 if bssid != fcs.addr1 else fcs.addr2

            return bssid, client

        return "", ""
