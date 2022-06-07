from scapy.compat import raw
from scapy.layers.dot11 import RadioTap
from scapy.utils import PcapReader

from app.packets.dot11 import Packet
from app.statistics import AccessPoint, Statistics

test_ap = AccessPoint(
    ssid="Test Wifi",
    bssid="aa:bb:cc:dd:ee:ff",
    security={"WPA2/PSK"},
    signal=15,
    channel=9,
)


def rebuild(packet: Packet) -> Packet:
    return RadioTap(raw(packet))


def test_create() -> None:
    assert Statistics() is not None


def test_process_beacon() -> None:
    statistics = Statistics()

    ap_beacon = test_ap.forge_beacon()
    statistics.process_packet(rebuild(ap_beacon))

    result_ap = statistics.get_ap(test_ap.bssid)
    assert result_ap == test_ap
    assert result_ap.ssid == test_ap.ssid
    assert result_ap.channel == test_ap.channel
    assert result_ap.security == test_ap.security


def test_process_response() -> None:
    pass


def test_all() -> None:
    statistics = Statistics()

    for packet in PcapReader("samples/WPA2-PSK.cap"):
        statistics.process_packet(packet)

    pass