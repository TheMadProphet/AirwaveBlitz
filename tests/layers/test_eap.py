from samples.raw_layers.eap import (
    raw_eapol_key_1,
    raw_eapol_key_2,
    raw_eapol_key_3,
    raw_eapol_key_4,
)
from scapy.layers.eap import EAPOL

from app.layers.eap import EAPOLKey


def test_eapol_key_1() -> None:
    eapol = EAPOL(raw_eapol_key_1)
    assert eapol.haslayer(EAPOLKey)

    eapol_key = eapol[EAPOLKey]
    assert eapol_key.descriptor_type == 2
    assert eapol_key.key_descriptor_version == 2
    assert eapol_key.key_type == 1
    assert eapol_key.key_len == 16
    assert eapol_key.key_info.install is False
    assert eapol_key.key_info.ack is True
    assert eapol_key.key_info.mic is False
    assert eapol_key.key_info.secure is False
    assert eapol_key.key_data_len == 22
    assert eapol_key.guess_key_number() == 1


def test_eapol_key_2() -> None:
    eapol = EAPOL(raw_eapol_key_2)
    assert eapol.haslayer(EAPOLKey)

    eapol_key = eapol[EAPOLKey]
    assert eapol_key.descriptor_type == 2
    assert eapol_key.key_descriptor_version == 2
    assert eapol_key.key_type == 1
    assert eapol_key.key_len == 16
    assert eapol_key.key_info.install is False
    assert eapol_key.key_info.ack is False
    assert eapol_key.key_info.mic is True
    assert eapol_key.key_info.secure is False
    assert eapol_key.key_data_len == 22
    assert eapol_key.guess_key_number() == 2


def test_eapol_key_3() -> None:
    eapol = EAPOL(raw_eapol_key_3)
    assert eapol.haslayer(EAPOLKey)

    eapol_key = eapol[EAPOLKey]
    assert eapol_key.descriptor_type == 2
    assert eapol_key.key_descriptor_version == 2
    assert eapol_key.key_type == 1
    assert eapol_key.key_len == 16
    assert eapol_key.key_info.install is True
    assert eapol_key.key_info.ack is True
    assert eapol_key.key_info.mic is True
    assert eapol_key.key_info.secure is True
    assert eapol_key.key_data_len == 56
    assert eapol_key.guess_key_number() == 3


def test_eapol_key_4() -> None:
    eapol = EAPOL(raw_eapol_key_4)
    assert eapol.haslayer(EAPOLKey)

    eapol_key = eapol[EAPOLKey]
    assert eapol_key.descriptor_type == 2
    assert eapol_key.key_descriptor_version == 2
    assert eapol_key.key_type == 1
    assert eapol_key.key_len == 16
    assert eapol_key.key_info.install is False
    assert eapol_key.key_info.ack is False
    assert eapol_key.key_info.mic is True
    assert eapol_key.key_info.secure is True
    assert eapol_key.key_data_len == 0
    assert eapol_key.key_data == b""
    assert eapol_key.guess_key_number() == 4
