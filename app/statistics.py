from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

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
from scapy.plist import PacketList

from app.layers.dot11 import Dot11Extensions, Packet
from app.layers.eap import EAPOLKey
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


# TODO: is this class necessary/useful? (yes if we can see client->ap signal strength)
@dataclass
class Device:
    mac: str
    bssid: str = ""  # ?
    signal: int = 0

    def __hash__(self) -> int:
        return self.mac.__hash__()


@dataclass
class Handshake:
    messages: Dict[int, Packet]

    def register_message(self, packet: Packet) -> None:
        if self.is_captured():
            return

        key = packet[EAPOLKey]
        key_number = key.guess_key_number()

        if key_number == 1:
            self.__reset()
            self.messages[key_number] = packet

        elif key_number == 2:
            self.messages[key_number] = packet

        elif key_number == 3:
            if key.nonce == self.messages[1].nonce:
                self.messages[key_number] = packet

        elif key_number == 4:
            if not key.nonce or key.nonce == self.messages[2].nonce:
                self.messages[key_number] = packet

    def is_captured(self) -> bool:
        if len(self.messages) == 4:
            return (
                self.messages[1].nonce == self.messages[3].nonce
                and self.messages[2].nonce == self.messages[4].nonce
            )

        return False

    def packets(self) -> PacketList:
        return PacketList(list(self.messages.values()))

    def __reset(self) -> None:
        self.messages = dict()


class Statistics:
    def __init__(self) -> None:
        self.access_points: Dict[str, AccessPoint] = dict()
        self.handshakes: Dict[Tuple[str, str], Handshake] = dict()
        self.devices: Set[Device] = set()
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

    def get_ap(self, bssid: str) -> AccessPoint:
        return self.access_points[bssid]

    def get_handshake(self, bssid: str) -> Optional[PacketList]:
        for (_client, _bssid), handshake in self.handshakes.items():
            if _bssid == bssid and handshake.is_captured():
                return handshake.packets()

        return None

    def __process_data(self, packet: Packet) -> None:
        assert Dot11 in packet and packet[Dot11].is_data()

        client, bssid = packet[Dot11].extract_addresses()
        if bssid not in self.access_points:
            return

        # TODO: signal
        # TODO: ignore 33:33:00:* 01:00:5e:*
        # https://superuser.com/questions/809679/what-is-the-mac-address-of-multicast-ipv6
        device = Device(mac=client, bssid=bssid)
        self.devices.add(device)
        self.access_points[bssid].devices.add(device)

    def __process_beacon(self, packet: Packet) -> None:
        assert Dot11Beacon in packet or Dot11ProbeResp in packet

        client, bssid = packet[Dot11].extract_addresses()
        if bssid in self.access_points:
            ap = self.access_points[bssid]
            ap.beacon_count += 1
        else:
            ap = AccessPoint.empty(bssid=bssid)

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

        # TODO: get channel from RatioTap if not available in tags

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

        client, bssid = packet[Dot11].extract_addresses()
        if (client, bssid) in self.handshakes:
            handshake = self.handshakes[client, bssid]
        else:
            handshake = Handshake(dict())

        handshake.register_message(packet)

        if handshake.is_captured():
            self.access_points[bssid].handshake = handshake
            # TODO: consider returning event when processing packet
            print("Captured entire handshake!")

        self.handshakes[client, bssid] = handshake
