import pytest
from scapy.compat import raw
from scapy.layers.dot11 import RadioTap
from scapy.packet import Packet
from scapy.utils import PcapNgReader, PcapReader

from app.entities.device import Device
from app.packet_processor import AccessPoint, PacketProcessor
from app.repository.entity_repository import EntityRepository
from app.repository.handshake_repository import HandshakeRepository

test_ap = AccessPoint(
    ssid="Test Wifi",
    bssid="aa:bb:cc:dd:ee:ff",
    security={"WPA2/PSK"},
    signal=15,
    channel=9,
)

access_points: EntityRepository[AccessPoint] = EntityRepository()
devices: EntityRepository[Device] = EntityRepository()
handshakes: HandshakeRepository = HandshakeRepository()

packet_processor = PacketProcessor(
    access_points=access_points,
    devices=devices,
    handshakes=handshakes,
)


def rebuild(packet: Packet) -> Packet:
    return RadioTap(raw(packet))


def test_beacon() -> None:

    ap_beacon = test_ap.forge_beacon()
    packet_processor.process_packet(rebuild(ap_beacon))

    result_ap = access_points.find(test_ap.bssid)
    assert result_ap == test_ap
    assert result_ap.ssid == test_ap.ssid
    assert result_ap.channel == test_ap.channel
    assert result_ap.security == test_ap.security


def test_response() -> None:
    pass


def test_all() -> None:
    # bssid = "64:a0:e7:af:47:4e"

    for packet in PcapReader("samples/captures/WPA2-PSK.cap"):
        packet_processor.process_packet(packet)


def test_simple() -> None:
    for packet in PcapNgReader("samples/captures/simple.pcapng"):
        packet_processor.process_packet(packet)


@pytest.mark.skip(reason="Takes too long. Run manually")
def test_big() -> None:
    for packet in PcapNgReader("samples/captures/big.pcapng"):
        packet_processor.process_packet(packet)
