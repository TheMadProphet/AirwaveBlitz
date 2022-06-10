import scapy.layers.eap as scapy
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    FieldLenField,
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
        BitField("smk", 0, 1),
        BitField("encrypted_key_data", 0, 1),
        BitField("request", 0, 1),
        BitField("error", 0, 1),
        BitField("secure", 0, 1),
        BitField("key_mic", 0, 1),
        BitField("key_ack", 0, 1),
        BitField("install", 0, 1),
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
        return self.key_ack == 1

    def is_pairwise(self) -> bool:
        return self.key_type == self.PAIRWISE

    # Returns handshake sequence number (1-4), or 0 if it can't be determined
    # TODO: better naming related to message/sequence number
    def guess_message_number(self) -> int:
        if self.is_pairwise():
            if self.is_sent_from_ap():
                if self.key_mic == 0:
                    return 1
                elif self.install == 1:
                    return 3
            else:
                if self.secure == 0:
                    return 2
                else:
                    return 4

        return 0


# TODO: create actual solution (i.e. rebind layers on application load, not through import)
bind_layers(scapy.EAPOL, EAPOLKey, type=3)
