from typing import Iterable, Type

import scapy.layers.dot11 as dot11
from scapy.compat import plain_str
from scapy.fields import ByteEnumField, ByteField, StrFixedLenField
from scapy.packet import Packet as ScapyPacket


class Packet(ScapyPacket):  # type: ignore
    @staticmethod
    def payloads(packet: ScapyPacket) -> Iterable[ScapyPacket]:
        payload = packet
        while payload:
            yield payload
            payload = payload.payload


class Dot11EltSSID(dot11.Dot11Elt):  # type: ignore
    name = "802.11 SSID Parameter Set"
    match_subclass = True
    fields_desc = [
        ByteEnumField("ID", 0, dot11._dot11_id_enum),
        ByteField("len", 0),
        StrFixedLenField("ssid", b"\0", length_from=lambda pkt: pkt.len),
    ]

    def value(self) -> str:
        return plain_str(self.ssid)


class Dot11EltDSSSet(dot11.Dot11EltDSSSet):  # type: ignore
    def value(self) -> int:
        return self.channel


class Dot11EltRSN(dot11.Dot11EltRSN):  # type: ignore
    def value(self) -> str:
        assert isinstance(self, Dot11EltRSN)

        wpa_version = "WPA2"

        if (
            any(x.suite == 8 for x in self.akm_suites)
            and all(x.suite not in [2, 6] for x in self.akm_suites)
            and self.mfp_capable
            and self.mfp_required
            and all(x.cipher not in [1, 2, 5] for x in self.pairwise_cipher_suites)
        ):
            wpa_version = "WPA3"
        elif (
            any(x.suite == 8 for x in self.akm_suites)
            and any(x.suite == 2 for x in self.akm_suites)
            and self.mfp_capable
            and not self.mfp_required
        ):
            wpa_version = "WPA3-transition"
        if self.akm_suites:
            auth = self.akm_suites[0].sprintf("%suite%")
            return wpa_version + "/%s" % auth
        else:
            return wpa_version


def register_elt(cls: Type[dot11.Dot11Elt], tag_id: int) -> None:
    cls.registered_ies[tag_id] = cls


register_elt(Dot11EltSSID, 0)
register_elt(Dot11EltDSSSet, 3)
register_elt(Dot11EltRSN, 48)
