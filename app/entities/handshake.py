from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from scapy.plist import PacketList

from app.layers.dot11 import Packet
from app.layers.eap import EAPOLKey


@dataclass
class Handshake:
    messages: Dict[int, Packet] = field(default_factory=dict)

    def register_message(self, packet: Packet) -> None:
        if self.is_captured():
            return

        key = packet[EAPOLKey]
        key_number = key.guess_key_number()

        if key_number == 1:
            self.__reset()
            self.messages[key_number] = packet

        elif key_number == 2:
            self.messages[key_number] = packet

        elif key_number == 3:
            if key.nonce == self.messages[1].nonce:  # TODO: self.messages[1] and ...
                self.messages[key_number] = packet

        elif key_number == 4:
            if not key.nonce or key.nonce == self.messages[2].nonce:
                self.messages[key_number] = packet

    def is_captured(self) -> bool:
        if len(self.messages) == 4:
            return (
                self.messages[1].nonce == self.messages[3].nonce
                and self.messages[2].nonce == self.messages[4].nonce
            )

        return False

    def packets(self) -> PacketList:
        return PacketList(list(self.messages.values()))

    def __reset(self) -> None:
        self.messages = dict()
