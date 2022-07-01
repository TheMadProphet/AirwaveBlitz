import time

import pytest

from app.interface import InterfaceMode, InterfaceState
from app.iw_ip import IwIp as InterfaceController

# TODO: Supply variables from commandline
iface_name = "wlx00c0caae5a41"
iface_mac = "00:c0:ca:ae:5a:41"
run_all_tests = False

pytest.skip(allow_module_level=True)


def test_list_interface() -> None:
    ifaces = InterfaceController.list_interfaces()
    contains_iface = False
    for iface in ifaces:
        contains_iface |= iface == iface_name

    assert contains_iface


def test_interface_state() -> None:
    # Setting interface to up may not be instantly reflected.
    # So sleep() is needed before state checks for test to pass.
    # Shouldn't become a problem during actual runtime.
    # TODO: Research
    InterfaceController.up(iface_name)
    time.sleep(2)
    assert InterfaceController.get_state(iface_name) == InterfaceState.UP
    InterfaceController.down(iface_name)
    assert InterfaceController.get_state(iface_name) == InterfaceState.DOWN

    InterfaceController.up(iface_name)
    InterfaceController.up(iface_name)
    time.sleep(2)
    assert InterfaceController.get_state(iface_name) == InterfaceState.UP
    InterfaceController.down(iface_name)
    assert InterfaceController.get_state(iface_name) == InterfaceState.DOWN
    InterfaceController.up(iface_name)
    time.sleep(2)
    assert InterfaceController.get_state(iface_name) == InterfaceState.UP


def test_interface_mode() -> None:
    InterfaceController.set_mode(iface_name, InterfaceMode.MANAGED)
    assert InterfaceController.get_mode(iface_name) == InterfaceMode.MANAGED

    InterfaceController.set_mode(iface_name, InterfaceMode.MONITOR)
    assert InterfaceController.get_mode(iface_name) == InterfaceMode.MONITOR

    InterfaceController.set_mode(iface_name, InterfaceMode.MANAGED)
    assert InterfaceController.get_mode(iface_name) == InterfaceMode.MANAGED


def test_interface_channel() -> None:
    InterfaceController.set_mode(iface_name, InterfaceMode.MONITOR)

    InterfaceController.set_channel(iface_name, 1)
    assert InterfaceController.get_channel(iface_name) == 1

    InterfaceController.set_channel(iface_name, 6)
    InterfaceController.set_channel(iface_name, 7)
    InterfaceController.set_channel(iface_name, 3)
    assert InterfaceController.get_channel(iface_name) == 3

    # Buffer issue for chn 14
    # InterfaceController.set_channel(14)

    with pytest.raises(ValueError):
        InterfaceController.set_channel(iface_name, 0)


def test_interface_channel_rapid_changes() -> None:
    InterfaceController.set_mode(iface_name, InterfaceMode.MONITOR)

    for test_iteration in range(5):
        for channel in range(1, 14):
            InterfaceController.set_channel(iface_name, channel)
            assert InterfaceController.get_channel(iface_name) == channel


@pytest.mark.skipif(not run_all_tests, reason="may loose original MAC if test fails")
def test_interface_mac() -> None:
    mac1 = "44:ee:bc:6c:76:ba"
    mac2 = "8e:a7:51:6d:60:41"

    assert InterfaceController.get_mac(iface_name) == iface_mac

    def set_mac(iface: str, mac: str) -> None:
        InterfaceController.down(iface)
        InterfaceController.set_mac(iface, mac)
        InterfaceController.up(iface)

    set_mac(iface_name, mac1)
    assert InterfaceController.get_mac(iface_name) == mac1

    set_mac(iface_name, mac2)
    assert InterfaceController.get_mac(iface_name) == mac2

    set_mac(iface_name, mac1)
    set_mac(iface_name, iface_mac)
    assert InterfaceController.get_mac(iface_name) == iface_mac


# Note: Name change is temporary, so this test is safe to run
def test_interface_name() -> None:
    assert InterfaceController.get_name(iface_name) == iface_name

    def set_name(iface: str, name: str) -> None:
        InterfaceController.down(iface)
        InterfaceController.set_name(iface, name)
        InterfaceController.up(name)

    set_name(iface_name, "ifacex")
    assert InterfaceController.get_name("ifacex") == "ifacex"

    set_name("ifacex", "12345")
    set_name("12345", "abcde")
    assert InterfaceController.get_name("abcde") == "abcde"

    InterfaceController.set_mode("abcde", InterfaceMode.MANAGED)
    InterfaceController.set_mode("abcde", InterfaceMode.MONITOR)
    assert InterfaceController.get_mode("abcde") == InterfaceMode.MONITOR

    InterfaceController.set_channel("abcde", 7)
    assert InterfaceController.get_channel("abcde") == 7

    set_name("abcde", iface_name)
    assert InterfaceController.get_name(iface_name) == iface_name
    assert InterfaceController.get_mode(iface_name) == InterfaceMode.MONITOR
    assert InterfaceController.get_channel(iface_name) == 7
