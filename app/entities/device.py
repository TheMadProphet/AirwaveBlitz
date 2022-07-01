from dataclasses import dataclass


# TODO: is this class necessary/useful? (yes if we can see client->ap signal strength)
@dataclass
class Device:
    mac: str
    bssid: str = ""  # ?
    signal: int = 0

    def __hash__(self) -> int:
        return self.mac.__hash__()
