import struct
from typing import Iterable, Type
from zlib import crc32

import scapy.layers.dot11 as dot11
from scapy.config import conf
from scapy.fields import FCSField
from scapy.packet import Packet as ScapyPacket
from scapy.packet import bind_layers


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
            return Dot11FCS
        return Dot11


class Dot11(dot11.Dot11):  # type: ignore
    MANAGEMENT = 0
    CONTROL = 1
    DATA = 2

    def is_management(self) -> bool:
        return self.type == self.MANAGEMENT

    def is_control(self) -> bool:
        return self.type == self.CONTROL

    def is_data(self) -> bool:
        return self.type == self.DATA


# Same as native, but subclass new Dot11 to inherit additional features
class Dot11FCS(Dot11):
    name = "802.11-FCS"
    match_subclass = True
    fields_desc = Dot11.fields_desc + [FCSField("fcs", None, fmt="<I")]

    def compute_fcs(self, s: bytes) -> bytes:
        return struct.pack("!I", crc32(s) & 0xFFFFFFFF)[::-1]

    def post_build(self, p: bytes, pay: bytes) -> bytes:
        p += pay
        if self.fcs is None:
            p = p[:-4] + self.compute_fcs(p[:-4])
        return p


# TODO: create actual solution (i.e. rebind layers on application load, not through import)
bind_layers(dot11.Dot11, Dot11, type=0)

conf.l2types.register(0x69, Dot11)
conf.l2types.register_num2layer(801, Dot11)
conf.l2types.register(0x7F, RadioTap)
conf.l2types.register_num2layer(803, RadioTap)
