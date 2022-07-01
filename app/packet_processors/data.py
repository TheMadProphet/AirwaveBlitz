from dataclasses import dataclass

from scapy.layers.dot11 import Dot11
from scapy.packet import Packet

from app.entities.access_point import AccessPoint
from app.entities.device import Device
from app.packet_processors.packet_processor import PacketProcessor
from app.repository.entity_repository import EntityNotFoundException, EntityRepository
from app.repository.handshake_repository import HandshakeRepository


@dataclass
class DataProcessor(PacketProcessor):
    access_points: EntityRepository[AccessPoint]
    devices: EntityRepository[Device]
    handshakes: HandshakeRepository

    @staticmethod
    def can_process(packet: Packet) -> bool:
        return Dot11 in packet and packet[Dot11].is_data()

    def process(self, packet: Dot11) -> None:
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
