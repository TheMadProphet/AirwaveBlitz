from __future__ import annotations

from scapy.packet import Packet

from app.entities.access_point import AccessPoint
from app.entities.device import Device
from app.repository.entity_repository import EntityRepository
from app.repository.handshake_repository import HandshakeRepository


class PacketProcessor:
    def __init__(
        self,
        access_points: EntityRepository[AccessPoint],
        devices: EntityRepository[Device],
        handshakes: HandshakeRepository,
    ):
        self.access_points = access_points
        self.devices = devices
        self.handshakes = handshakes

    @staticmethod
    def can_process(packet: Packet) -> bool:
        return True

    def process(self, packet: Packet) -> None:
        pass
