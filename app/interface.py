import re
from dataclasses import dataclass
from enum import Enum
from typing import Final


class InterfaceMode(Enum):
    MANAGED = "managed"
    MONITOR = "monitor"


class InterfaceState(Enum):
    UP = "up"
    DOWN = "down"
    DORMANT = "dormant"


@dataclass(frozen=True)
class Interface:
    name: str
    mode: InterfaceMode
    channel: int
    mac: str
    is_up: bool
    HOP_INTERVAL: Final = 0.15

    # def __init__(self):
    # if not interface_controller.is_valid_iface(iface):
    #    raise ValueError("Invalid interface")

    # self.interface_controller = interface_controller
    # self.channel_hop_process = Process(
    #    target=self.channel_hop, name="channel hopper"
    # )

    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        return (
            re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower())
            is not None
        )
