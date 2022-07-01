from dataclasses import dataclass


@dataclass
class Device:
    mac: str
    bssid: str = ""  # TODO: Does this have an actual use-case?
    signal: int = 0

    def __hash__(self) -> int:
        return self.mac.__hash__()
