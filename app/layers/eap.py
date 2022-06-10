import scapy.layers.eap as scapy
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    FieldLenField,
    FlagsField,
    LongField,
    NBytesField,
    ShortField,
    StrLenField,
)
from scapy.packet import Packet, bind_layers

key_descriptor_versions = {
    1: "ARC4 Cipher, HMAC-MD5",
    2: "AES Cipher, HMAC-SHA-1-128",
    3: "AES Cipher, AES-128-CMAC",
}


# 802.11-2016 - 12.7.2
# 801.1X-2010 - 11.9
class EAPOLKey(Packet):  # type: ignore
    PAIRWISE = 0x1

    fields_desc = [
        ByteEnumField("descriptor_type", 0, {1: "RC4", 2: "IEEE 802.11"}),
        BitField("reserved14_15", 0, 2),
        FlagsField(
            "key_info",
            0,
            8,
            [
                "install",
                "ack",
                "mic",
                "secure",
                "error",
                "request",
                "encrypted_key_data",
                "smk",
            ],
        ),
        BitField("reserved4_5", 0, 2),
        BitEnumField("key_type", 0, 1, {0: "Group Key", 1: "Pairwise Key"}),
        BitEnumField("key_descriptor_version", 0, 3, key_descriptor_versions),
        ShortField("key_len", None),
        LongField("replay_counter", 0),
        NBytesField("nonce", 0, 32),
        NBytesField("key_iv", 0, 16),
        LongField("rsc", 0),
        LongField("reserved", 0),
        NBytesField("mic", 0, 16),
        FieldLenField("key_data_len", None, length_of="key_data"),
        StrLenField("key_data", b"", length_from=lambda pkt: pkt.key_data_len),
    ]

    def is_sent_from_ap(self) -> bool:
        return self.key_info.ack

    def is_pairwise(self) -> bool:
        return self.key_type == self.PAIRWISE

    # Returns handshake sequence number (1-4), or 0 if it can't be determined
    # TODO: better naming related to message/sequence number
    def guess_key_number(self) -> int:
        if self.is_pairwise():
            if self.is_sent_from_ap():
                if not self.key_info.mic:
                    return 1
                elif self.key_info.install:
                    return 3
            else:
                if self.key_info.secure is False:
                    return 2
                else:
                    return 4

        return 0


# TODO: create actual solution (i.e. rebind layers on application load, not through import)
bind_layers(scapy.EAPOL, EAPOLKey, type=3)
