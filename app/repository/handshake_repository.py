from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from app.packet_processor import Handshake
from app.repository.entity_repository import EntityRepository


@dataclass
class HandshakeRepository:
    handshakes: EntityRepository[Handshake] = field(default_factory=EntityRepository)

    def find(self, mac: str, bssid: str) -> Handshake:
        return self.handshakes.find(self.__concatenate(mac, bssid))

    def find_all_for_ap(self, mac: str) -> List[Handshake]:
        result: List[Handshake] = []
        for mac_bssid, handshake in self.handshakes.find_all().items():
            _, bssid = self.__split(mac_bssid)
            if bssid == mac:
                result.append(handshake)

        return result

    def find_captured_for_ap(self, bssid: str) -> Optional[Handshake]:
        for handshake in self.find_all_for_ap(bssid):
            if handshake.is_captured():
                return handshake

        return None

    def save(self, mac: str, bssid: str, handshake: Handshake) -> None:
        self.handshakes.save(self.__concatenate(mac, bssid), handshake)

    @staticmethod
    def __concatenate(mac: str, bssid: str) -> str:
        return f"{mac}|{bssid}"

    @staticmethod
    def __split(mac_bssid: str) -> Tuple[str, str]:
        addresses = mac_bssid.split("|")
        assert len(addresses) == 2

        return addresses[0], addresses[1]
