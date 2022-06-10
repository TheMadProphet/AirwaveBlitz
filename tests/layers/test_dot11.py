from samples.raw_layers.dot11 import (
    control_ack_1,
    control_ack_2,
    data_null,
    data_qos_1,
    data_qos_null_1,
    management_beacon_1,
    management_probe_response,
)
from scapy.layers.dot11 import Dot11

import app.layers.dot11

app.layers.dot11.Dot11Extensions.patch()
# TODO: Not here ^


def test_has_type_helpers() -> None:
    assert hasattr(Dot11, "is_management")
    assert hasattr(Dot11, "is_control")
    assert hasattr(Dot11, "is_data")


def test_type_management_beacon() -> None:
    beacon = Dot11(management_beacon_1)
    assert beacon.is_management() is True
    assert beacon.is_control() is False
    assert beacon.is_data() is False


def test_type_management_probe_response() -> None:
    probe_response = Dot11(management_probe_response)
    assert probe_response.is_management() is True
    assert probe_response.is_control() is False
    assert probe_response.is_data() is False


def test_type_control_ack1() -> None:
    ack = Dot11(control_ack_1)
    assert ack.is_management() is False
    assert ack.is_control() is True
    assert ack.is_data() is False


def test_type_control_ack2() -> None:
    ack = Dot11(control_ack_2)
    assert ack.is_management() is False
    assert ack.is_control() is True
    assert ack.is_data() is False


def test_type_data_null() -> None:
    null_data = Dot11(data_null)
    assert null_data.is_management() is False
    assert null_data.is_control() is False
    assert null_data.is_data() is True


def test_type_data_qos_null() -> None:
    qos_null = Dot11(data_qos_null_1)
    assert qos_null.is_management() is False
    assert qos_null.is_control() is False
    assert qos_null.is_data() is True


def test_type_data_qos() -> None:
    null_data = Dot11(data_qos_1)
    assert null_data.is_management() is False
    assert null_data.is_control() is False
    assert null_data.is_data() is True
