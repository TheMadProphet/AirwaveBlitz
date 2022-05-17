import time

import pytest

from interface import Interface, InterfaceMode

iface_name = "wlx00c0caae5a41"
iface_mac = "00:c0:ca:ae:5a:41"
run_all_tests = False


def test_should_create_interface() -> None:
    a = 1
    with pytest.raises(ValueError):
        Interface("")

    with pytest.raises(ValueError):
        Interface("invalidiface")

    ifaces = Interface.list_interfaces()
    for iface in ifaces:
        assert Interface(iface) is not None


def test_interface_state() -> None:
    iface = Interface(iface_name)

    # Setting interface to up may not be instantly reflected.
    # So sleep() is needed before state checks for test to pass.
    # Shouldn't become a problem during actual runtime.
    # TODO: Research
    iface.up()
    time.sleep(2)
    assert iface.is_up() is True
    iface.down()
    assert iface.is_up() is False

    iface.up()
    iface.up()
    time.sleep(2)
    assert iface.is_up() is True
    iface.down()
    assert iface.is_up() is False

    iface.up()
    iface.down()
    iface.up()
    iface.down()
    iface.down()
    iface.up()
    time.sleep(2)
    assert iface.is_up() is True


def test_interface_mode() -> None:
    iface = Interface(iface_name)

    iface.set_mode(InterfaceMode.MANAGED)
    assert iface.get_mode() == InterfaceMode.MANAGED

    iface.set_mode(InterfaceMode.MONITOR)
    assert iface.get_mode() == InterfaceMode.MONITOR

    iface.set_mode(InterfaceMode.MANAGED)
    assert iface.get_mode() == InterfaceMode.MANAGED


def test_interface_channel() -> None:
    iface = Interface(iface_name)
    iface.set_mode(InterfaceMode.MONITOR)

    iface.set_channel(1)
    assert iface.get_channel() == 1

    iface.set_channel(6)
    iface.set_channel(7)
    iface.set_channel(3)
    assert iface.get_channel() == 3

    # Buffer issue for chn 14
    # iface.set_channel(14)

    with pytest.raises(ValueError):
        iface.set_channel(0)


def test_interface_channel_rapid_changes() -> None:
    iface = Interface(iface_name)
    iface.set_mode(InterfaceMode.MONITOR)

    for test_iteration in range(5):
        for channel in range(1, 14):
            iface.set_channel(channel)
            assert iface.get_channel() == channel


def test_interface_channel_hop() -> None:
    iface = Interface(iface_name)
    iface.set_mode(InterfaceMode.MONITOR)

    assert iface.is_channel_hopping() is False

    iface.start_channel_hop()
    assert iface.is_channel_hopping() is True
    # time.sleep(5)  # Time to manually check if channel is changing
    iface.stop_channel_hop()
    assert iface.is_channel_hopping() is False

    iface.start_channel_hop()
    assert iface.is_channel_hopping() is True
    # time.sleep(5)  # Time to manually check if channel is changing
    iface.stop_channel_hop()
    assert iface.is_channel_hopping() is False

    iface.start_channel_hop()
    with pytest.raises(AssertionError):
        iface.start_channel_hop()

    iface.stop_processes()
    assert iface.is_channel_hopping() is False

    iface.start_channel_hop()
    iface.set_channel(9)
    assert iface.is_channel_hopping() is False
    assert iface.get_channel() == 9


@pytest.mark.skipif(not run_all_tests, reason="may loose original MAC if test fails")
def test_interface_mac() -> None:
    iface = Interface(iface_name)
    mac1 = "44:ee:bc:6c:76:ba"
    mac2 = "8e:a7:51:6d:60:41"

    assert iface.get_mac() == iface_mac

    iface.set_mac(mac1)
    assert iface.get_mac() == mac1

    iface.set_mac(mac2)
    assert iface.get_mac() == mac2

    iface.set_mac(mac1)
    iface.set_mac(iface_mac)
    assert iface.get_mac() == iface_mac

    with pytest.raises(ValueError):
        iface.set_mac("aa:bb:cc:dd:ee:f")

    with pytest.raises(ValueError):
        iface.set_mac("aa:bb:22:a:3:")

    assert iface.get_mac() == iface_mac


# Note: Name change is temporary, so this test is safe to run
def test_interface_name() -> None:
    iface = Interface(iface_name)
    assert iface.get_name() == iface_name

    iface.set_name("ifacex")
    assert iface.get_name() == "ifacex"

    iface.set_name("12345")
    iface.set_name("abcde")
    assert iface.get_name() == "abcde"

    iface.set_mode(InterfaceMode.MANAGED)
    iface.set_mode(InterfaceMode.MONITOR)
    assert iface.get_mode() == InterfaceMode.MONITOR

    iface.set_channel(7)
    assert iface.get_channel() == 7

    iface.set_name(iface_name)
    assert iface.get_name() == iface_name
    assert iface.get_mode() == InterfaceMode.MONITOR
    assert iface.get_channel() == 7
