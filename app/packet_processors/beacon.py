from dataclasses import dataclass

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltMicrosoftWPA,
    Dot11ProbeResp,
)
from scapy.packet import Packet

from app.entities.access_point import AccessPoint
from app.entities.device import Device
from app.layers.elt import Dot11EltDSSSet, Dot11EltRSN, Dot11EltSSID
from app.packet_processors.packet_processor import PacketProcessor
from app.repository.entity_repository import EntityNotFoundException, EntityRepository
from app.repository.handshake_repository import HandshakeRepository


@dataclass
class BeaconProcessor(PacketProcessor):
    access_points: EntityRepository[AccessPoint]
    devices: EntityRepository[Device]
    handshakes: HandshakeRepository

    @staticmethod
    def can_process(packet: Packet) -> bool:
        return Dot11Beacon in packet or Dot11ProbeResp in packet

    def process(self, packet: Dot11) -> None:
        client, bssid = packet[Dot11].extract_addresses()

        try:
            ap = self.access_points.find(bssid)
            ap.beacon_count += 1
        except EntityNotFoundException:
            ap = AccessPoint.empty(bssid=bssid)

        for elt in packet.iterpayloads():
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
