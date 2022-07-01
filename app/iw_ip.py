import json
import subprocess
from shlex import split
from typing import Dict, Iterable, List

import netifaces as ni

from app.entities.interface import InterfaceMode, InterfaceState


class IwIpException(Exception):
    pass


class IwIp:
    @staticmethod
    def run_command(command: str) -> str:
        proc = subprocess.Popen(
            split(command), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        if proc.stderr:
            stderr = proc.stderr.read().decode("utf-8")
            if stderr:
                raise IwIpException(stderr)

        stdout = proc.stdout.read().decode("utf-8") if proc.stdout else ""

        return stdout

    @staticmethod
    def run_iw(iface: str = "", args: str = "") -> str:
        # TODO: Is it right to use sudo here?
        return IwIp.run_command(f"sudo iw dev {iface} {args}")

    @staticmethod
    def run_ip(args: str = "", json_ouput: bool = False) -> str:
        # TODO: Is it right to use sudo here?
        return IwIp.run_command(f"sudo ip{' -j' if json_ouput else ''} link {args}")

    @staticmethod
    def list_interfaces() -> Iterable[str]:
        result: List[str] = []
        stdout = IwIp.run_iw()
        for line in stdout.split("\n"):
            args = line.split()
            if len(args) == 2:
                key, value = args
                if key == "Interface":
                    result.append(value)

        return result

    @staticmethod
    def iw_info(iface: str) -> Dict[str, str]:
        result: Dict[str, str] = {}
        stdout = IwIp.run_iw(iface, "info")
        for line in stdout.split("\n"):
            args = line.split()
            if len(args) > 1:
                if len(args) == 2:
                    key, value = args
                    result[key] = value
                else:
                    result[args[0]] = args[1]

        return result

    @staticmethod
    def ip_info(iface: str) -> Dict:  # type: ignore
        stdout = IwIp.run_ip(f"show {iface}", json_ouput=True)

        return json.loads(stdout)[0]

    @staticmethod
    def up(iface: str) -> None:
        IwIp.run_ip(f"set {iface} mode DEFAULT")
        IwIp.run_ip(f"set {iface} up")

    @staticmethod
    def down(iface: str) -> None:
        IwIp.run_ip(f"set {iface} down")

    @staticmethod
    def get_state(iface: str) -> InterfaceState:
        state = IwIp.ip_info(iface)["operstate"]
        return InterfaceState[state]

    @staticmethod
    def get_mode(iface: str) -> InterfaceMode:
        mode = IwIp.iw_info(iface)["type"]
        return InterfaceMode[mode]

    @staticmethod
    def set_mode(iface: str, mode: InterfaceMode) -> None:
        IwIp.run_iw(iface, "set type " + mode.value)

    @staticmethod
    def get_channel(iface: str) -> int:
        return int(IwIp.iw_info(iface)["channel"])

    # Buffer issue when setting channel to 14. TODO: Research
    @staticmethod
    def set_channel(iface: str, channel: int) -> None:
        if channel <= 0:
            raise ValueError(f"Invalid channel: {channel}")

        IwIp.run_iw(iface, "set channel " + str(channel))

    @staticmethod
    def get_mac(iface: str) -> str:
        return IwIp.ip_info(iface)["address"].lower()

    @staticmethod
    def set_mac(iface: str, mac: str) -> None:
        IwIp.run_ip(f"set dev {iface} address {mac}")

    @staticmethod
    def get_name(iface: str) -> str:
        return IwIp.ip_info(iface)["ifname"]

    @staticmethod
    def set_name(iface: str, name: str) -> None:
        IwIp.run_ip(f"set {iface} name {name}")

    @staticmethod
    def is_connected(iface: str) -> bool:
        pass

    # TODO
    @staticmethod
    def is_valid_iface(iface: str) -> bool:
        try:
            ni.ifaddresses(iface)
            return True
        except ValueError:
            return False
