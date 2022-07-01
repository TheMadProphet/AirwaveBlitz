import time

import pytest

from app.entities.interface import Interface
from app.interface_service import InterfaceService
from app.iw_ip import IwIp

# TODO: Supply variables from commandline
iface_name = "wlx00c0caae5a41"
iface_mac = "00:c0:ca:ae:5a:41"
run_all_tests = False
iface_service = InterfaceService(IwIp())

pytest.skip(allow_module_level=True)


def test_list_interface() -> None:
    ifaces = iface_service.list_interface()
    contains_iface = False
    for iface in ifaces:
        contains_iface |= iface == iface_name

    assert contains_iface


@pytest.mark.skipif(not run_all_tests, reason="may loose original MAC if test fails")
def test_interface_mac() -> None:
    def interface() -> Interface:
        return iface_service.get_interface(iface_name)

    mac1 = "44:ee:bc:6c:76:ba"
    mac2 = "8e:a7:51:6d:60:41"

    assert interface().mac == iface_mac

    iface_service.set_mac(iface_name, mac1)
    assert interface().mac == mac1

    iface_service.set_mac(iface_name, mac2)
    assert interface().mac == mac2

    iface_service.set_mac(iface_name, mac1)
    iface_service.set_mac(iface_name, iface_mac)
    assert interface().mac == iface_mac

    with pytest.raises(ValueError):
        iface_service.set_mac(iface_name, "aa:bb:cc:dd:ee:f")

    with pytest.raises(ValueError):
        iface_service.set_mac(iface_name, "aa:bb:22:a:3:")

    assert interface().mac == iface_mac


# TODO: Fails without root privilege
def test_monitor() -> None:
    iface_service.monitor_channel(iface_name, 5, lambda x: None)
    time.sleep(5)
    assert iface_service.is_monitoring() is True

    packets = iface_service.stop_monitoring()
    assert packets > 1
    assert iface_service.is_monitoring() is False

    iface_service.monitor_all_channels(iface_name, lambda x: None)
    time.sleep(5)
    assert iface_service.is_monitoring() is True

    packets = iface_service.stop_monitoring()
    assert packets > 1
    assert iface_service.is_monitoring() is False
