from samples.raw.dot11_packets import management_beacon_1
from scapy.compat import raw
from scapy.layers.dot11 import RadioTap
from scapy.packet import Packet

from app.entities.access_point import AccessPoint
from app.entities.device import Device
from app.packet_processors.beacon import BeaconProcessor
from app.repository.entity_repository import EntityRepository
from app.repository.handshake_repository import HandshakeRepository

access_points: EntityRepository[AccessPoint] = EntityRepository()
devices: EntityRepository[Device] = EntityRepository()
handshakes: HandshakeRepository = HandshakeRepository()


beacon_processor = BeaconProcessor(
    access_points=access_points,
    devices=devices,
    handshakes=handshakes,
)


def rebuild(packet: Packet) -> Packet:
    return RadioTap(raw(packet))


def test_beacon_from_entity() -> None:
    ap = AccessPoint(
        ssid="Test Wifi",
        bssid="aa:bb:cc:dd:ee:ff",
        security={"WPA2/PSK"},
        signal=15,
        channel=9,
    )

    ap_beacon = ap.forge_beacon()
    beacon_processor.process(rebuild(ap_beacon))

    result_ap = access_points.find(ap.bssid)
    assert result_ap == ap
    assert result_ap.ssid == ap.ssid
    assert result_ap.channel == ap.channel
    assert result_ap.security == ap.security


def test_beacon_from_sample() -> None:
    ap = AccessPoint(
        ssid="TEST1",
        bssid="64:a0:e7:af:47:4e",
        security={"WPA2/PSK"},
        signal=32,
        channel=36,
    )

    beacon_processor.process(RadioTap(management_beacon_1))

    result_ap = access_points.find(ap.bssid)
    assert result_ap == ap
    assert result_ap.ssid == ap.ssid
    assert result_ap.channel == ap.channel  # TODO
    assert result_ap.security == ap.security
