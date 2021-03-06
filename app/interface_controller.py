from typing import Iterable, Protocol

from app.entities.interface import InterfaceMode, InterfaceState


class InterfaceController(Protocol):
    def list_interfaces(self) -> Iterable[str]:
        pass

    def up(self, iface: str) -> None:
        pass

    def down(self, iface: str) -> None:
        pass

    def get_state(self, iface: str) -> InterfaceState:
        pass

    def get_mode(self, iface: str) -> InterfaceMode:
        pass

    def set_mode(self, iface: str, mode: InterfaceMode) -> None:
        pass

    def get_channel(self, iface: str) -> int:
        pass

    def set_channel(self, iface: str, channel: int) -> None:
        pass

    def get_mac(self, iface: str) -> str:
        pass

    def set_mac(self, iface: str, mac: str) -> None:
        pass

    def get_name(self, iface: str) -> str:
        pass

    def set_name(self, iface: str, name: str) -> None:
        pass

    def is_connected(self, iface: str) -> bool:
        pass

    def is_valid_iface(self, iface: str) -> bool:
        pass
