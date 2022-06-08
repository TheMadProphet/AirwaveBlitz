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
from scapy.packet import bind_layers, split_layers

key_descriptor_versions = {
    1: "ARC4 Cipher, HMAC-MD5",
    2: "AES Cipher, HMAC-SHA-1-128",
    3: "AES Cipher, AES-128-CMAC",
}


# 802.11-2016 - 12.7.2 & 801.1X-2010 - 11.9
class EAPOL(scapy.EAPOL):  # type: ignore
    fields_desc = scapy.EAPOL.fields_desc + [
        ByteEnumField("key_descriptor_type", 0, {1: "RC4", 2: "IEEE 802.11"}),
        BitField("reserved", 0, 2),  # TODO: multiple fields under "reserved"?
        BitField("smk", 0, 1),
        BitField("encrypted_key_data", 0, 1),
        BitField("request", 0, 1),
        BitField("error", 0, 1),
        BitField("secure", 0, 1),
        BitField("key_mic", 0, 1),
        BitField("key_ack", 0, 1),
        BitField("install", 0, 1),
        BitField("reserved", 0, 2),
        BitEnumField("key_type", 0, 1, {0: "Group Key", 1: "Pairwise Key"}),
        BitEnumField("key_descriptor_version", 0, 3, key_descriptor_versions),
        ShortField("key_len", None),
        LongField("replay_counter", 0),
        NBytesField("nonce", 0, 32),
        NBytesField("key_iv", 0, 16),
        LongField("key_rsc", 0),
        LongField("reserved", 0),
        NBytesField("mic", 0, 16),
        FieldLenField("key_data_len", None, length_of="key_data"),
        StrLenField("key_data", b"", length_from=lambda pkt: pkt.key_data_len),
    ]

    def is_sent_from_ap(self) -> bool:
        return self.key_ack == 1

    # Returns handshake sequence number (1-4), or 0 if it can't be determined
    def get_handshake_sequence(self) -> int:
        # EAPOL-Key and Pairwise
        if self.type == 0x3 and self.key_type == 1:
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

    @staticmethod
    def rebind() -> None:
        overload_fields = EAPOL().overload_fields.items()
        for packet_type, fields in overload_fields:
            split_layers(packet_type, scapy.EAPOL, fields)
            bind_layers(packet_type, EAPOL, fields)


EAPOL.rebind()
