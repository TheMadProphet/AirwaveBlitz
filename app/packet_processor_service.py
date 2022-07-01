from __future__ import annotations

from typing import List

from scapy.packet import Packet

from app.entities.access_point import AccessPoint
from app.entities.device import Device
from app.layers.dot11 import Dot11Extensions
from app.packet_processors.beacon import BeaconProcessor
from app.packet_processors.data import DataProcessor
from app.packet_processors.eapol_key import EAPOLKeyProcessor
from app.packet_processors.packet_processor import PacketProcessor
from app.repository.entity_repository import EntityRepository
from app.repository.handshake_repository import HandshakeRepository

Dot11Extensions.patch()


class PacketProcessorService:
    def __init__(
        self,
        access_points: EntityRepository[AccessPoint],
        devices: EntityRepository[Device],
        handshakes: HandshakeRepository,
    ):
        self.access_points = access_points
        self.devices = devices
        self.handshakes = handshakes
        self.processors: List[PacketProcessor] = [
            DataProcessor(
                access_points=access_points, devices=devices, handshakes=handshakes
            ),
            BeaconProcessor(
                access_points=access_points, devices=devices, handshakes=handshakes
            ),
            EAPOLKeyProcessor(
                access_points=access_points, devices=devices, handshakes=handshakes
            ),
        ]

    def process(self, packet: Packet) -> None:
        for processor in self.processors:
            if processor.can_process(packet):
                processor.process(packet)
