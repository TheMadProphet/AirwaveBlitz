from dataclasses import dataclass

from scapy.layers.dot11 import Dot11
from scapy.packet import Packet

from app.entities.access_point import AccessPoint
from app.entities.device import Device
from app.entities.handshake import Handshake
from app.layers.eap import EAPOLKey
from app.packet_processors.packet_processor import PacketProcessor
from app.repository.entity_repository import EntityNotFoundException, EntityRepository
from app.repository.handshake_repository import HandshakeRepository


@dataclass
class EAPOLKeyProcessor(PacketProcessor):
    access_points: EntityRepository[AccessPoint]
    devices: EntityRepository[Device]
    handshakes: HandshakeRepository

    @staticmethod
    def can_process(packet: Packet) -> bool:
        return EAPOLKey in packet

    def process(self, packet: Dot11) -> None:
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
