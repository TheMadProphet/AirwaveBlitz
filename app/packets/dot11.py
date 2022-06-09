from typing import Iterable, Type

import scapy.layers.dot11 as dot11
from scapy.compat import plain_str
from scapy.config import conf
from scapy.fields import ByteEnumField, ByteField, StrFixedLenField
from scapy.packet import Packet as ScapyPacket


class Packet(ScapyPacket):  # type: ignore
    @staticmethod
    def payloads(packet: ScapyPacket) -> Iterable[ScapyPacket]:
        payload = packet
        while payload:
            yield payload
            payload = payload.payload


class RadioTap(dot11.RadioTap):  # type: ignore
    def guess_payload_class(self, payload: Packet) -> Type[Packet]:
        if self.present and self.present.Flags and self.Flags.FCS:
            return dot11.Dot11FCS
        return Dot11


class Dot11(dot11.Dot11):  # type: ignore
    # TODO: is_management()
    pass


class Dot11EltSSID(dot11.Dot11Elt):  # type: ignore
    name = "802.11 SSID Parameter Set"
    match_subclass = True
    fields_desc = [
        ByteEnumField("ID", 0, dot11._dot11_id_enum),
        ByteField("len", 0),
        StrFixedLenField("ssid", b"", length_from=lambda pkt: pkt.len),
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


# TODO: create actual solution (i.e. rebind packets on application load, not through import)
register_elt(Dot11EltSSID, 0)
register_elt(Dot11EltDSSSet, 3)
register_elt(Dot11EltRSN, 48)

conf.l2types.register(0x69, Dot11)
conf.l2types.register_num2layer(801, Dot11)
conf.l2types.register(0x7F, RadioTap)
conf.l2types.register_num2layer(803, RadioTap)
