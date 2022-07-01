from __future__ import annotations

from dataclasses import dataclass

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltMicrosoftWPA,
    Dot11ProbeResp,
)

from app.entities.access_point import AccessPoint
from app.entities.device import Device
from app.entities.handshake import Handshake
from app.layers.dot11 import Dot11Extensions, Packet
from app.layers.eap import EAPOLKey
from app.layers.elt import Dot11EltDSSSet, Dot11EltRSN, Dot11EltSSID
from app.repository.entity_repository import EntityNotFoundException, EntityRepository
from app.repository.handshake_repository import HandshakeRepository

Dot11Extensions.patch()


@dataclass
class PacketProcessor:
    access_points: EntityRepository[AccessPoint]
    devices: EntityRepository[Device]
    handshakes: HandshakeRepository

    def process_packet(self, packet: Packet) -> None:
        if Dot11 in packet:
            if packet[Dot11].is_data():
                self.__process_data(packet)
            if Dot11Beacon in packet or Dot11ProbeResp in packet:
                self.__process_beacon(packet)
            if EAPOLKey in packet:
                self.__process_eapol_key(packet)

    def __process_data(self, packet: Packet) -> None:
        assert Dot11 in packet and packet[Dot11].is_data()

        client, bssid = packet[Dot11].extract_addresses()

        # TODO: signal
        # TODO: ignore 33:33:00:* 01:00:5e:*
        # https://superuser.com/questions/809679/what-is-the-mac-address-of-multicast-ipv6
        device = Device(mac=client, bssid=bssid)
        self.devices.save(client, device)

        try:
            ap = self.access_points.find(bssid)
        except EntityNotFoundException:
            ap = AccessPoint.empty(bssid=bssid)

        ap.devices.add(device)
        self.access_points.save(bssid, ap)

    def __process_beacon(self, packet: Packet) -> None:
        assert Dot11Beacon in packet or Dot11ProbeResp in packet

        client, bssid = packet[Dot11].extract_addresses()

        try:
            ap = self.access_points.find(bssid)
            ap.beacon_count += 1
        except EntityNotFoundException:
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

        # TODO: try to get channel from RatioTap if not available in tags

        if not ap.security and hasattr(packet, "cap"):
            if packet.cap.privacy:
                ap.security.add("WEP")
            else:
                ap.security.add("OPN")

        self.access_points.save(bssid, ap)

    def __process_eapol_key(self, packet: Packet) -> None:
        assert EAPOLKey in packet

        client, bssid = packet[Dot11].extract_addresses()

        try:
            handshake = self.handshakes.find(client, bssid)
        except EntityNotFoundException:
            handshake = Handshake()

        handshake.register_message(packet)
        self.handshakes.save(client, bssid, handshake)

        if handshake.is_captured():
            # TODO: consider returning event when processing packet
            print("Captured entire handshake!")

            try:
                ap = self.access_points.find(bssid)
                ap.handshake = handshake
                self.access_points.save(bssid, ap)
            except EntityNotFoundException:
                pass
