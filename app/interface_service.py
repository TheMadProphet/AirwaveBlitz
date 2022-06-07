import time
from dataclasses import dataclass
from multiprocessing import Process
from typing import Any, Callable, Iterable

from scapy.all import AsyncSniffer
from scapy.packet import Packet
from scapy.plist import PacketList

from app.interface import Interface, InterfaceMode
from app.interface_controller import InterfaceController


@dataclass
class InterfaceService:
    interface_controller: InterfaceController
    channel_hop_process: Process = Process()
    sniffer: AsyncSniffer = AsyncSniffer()

    def list_interface(self) -> Iterable[str]:
        return self.interface_controller.list_interfaces()

    # TODO: optimize? (move to controller)
    def get_interface(self, iface: str) -> Interface:
        return Interface(
            name=self.interface_controller.get_name(iface),
            mode=self.interface_controller.get_mode(iface),
            channel=self.interface_controller.get_channel(iface),
            mac=self.interface_controller.get_mac(iface),
            state=self.interface_controller.get_state(iface),
        )

    # TODO: move out monitor-related service
    def monitor_channel(
        self, iface_name: str, channel: int, packet_processor: Callable[[Packet], Any]
    ) -> None:
        self.__set_mode(iface_name, InterfaceMode.MONITOR)
        self.interface_controller.set_channel(iface_name, channel)

        self.sniffer = AsyncSniffer(iface=iface_name, prn=packet_processor)
        self.sniffer.start()

    def monitor_all_channels(
        self, iface_name: str, packet_processor: Callable[[Packet], Any]
    ) -> None:
        self.__set_mode(iface_name, InterfaceMode.MONITOR)
        self.__start_channel_hop(iface_name)

        self.sniffer = AsyncSniffer(iface=iface_name, prn=packet_processor)
        self.sniffer.start()

    def is_monitoring(self) -> bool:
        return self.sniffer.running

    def stop_monitoring(self) -> PacketList:
        if self.sniffer.running:
            if self.__is_channel_hopping():
                self.__stop_channel_hop()

            return self.sniffer.stop()  # TODO: join?

    def set_mac(self, iface_name: str, mac: str) -> None:
        if not Interface.is_valid_mac(mac):
            raise ValueError("invalid mac address")

        self.stop_processes()
        self.interface_controller.down(iface_name)
        self.interface_controller.set_mac(iface_name, mac)
        self.interface_controller.up(iface_name)

    def get_mac(self, iface_name: str) -> str:
        return self.interface_controller.get_mac(iface_name)

    def set_name(self, iface_name: str, name: str) -> None:
        name = name.strip()
        if not name:
            raise ValueError("name cannot be empty")
        if len(name.split()) > 1:
            raise ValueError("name cannot contain spaces")

        self.stop_processes()
        self.interface_controller.down(iface_name)
        self.interface_controller.set_name(iface_name, name)
        self.interface_controller.up(name)

    def __set_channel(self, iface_name: str, channel: int) -> None:
        if self.__is_channel_hopping():
            self.__stop_channel_hop()

        self.interface_controller.set_channel(iface_name, channel)

    def __set_mode(self, iface_name: str, mode: InterfaceMode) -> None:
        self.stop_processes()
        self.interface_controller.down(iface_name)
        self.interface_controller.set_mode(iface_name, mode)
        self.interface_controller.up(iface_name)

    def __start_channel_hop(self, iface_name: str) -> None:
        assert self.__is_channel_hopping() is False, "channel is already hopping"

        self.channel_hop_process = Process(
            target=self.__channel_hop(iface_name), name="channel hopper"
        )
        self.channel_hop_process.start()

    def __channel_hop(self, iface_name: str) -> Callable[[], None]:
        def channel_hop_for_interface() -> None:
            while True:
                try:
                    for channel in range(1, 14):
                        self.interface_controller.set_channel(iface_name, channel)
                        time.sleep(Interface.HOP_INTERVAL)
                except KeyboardInterrupt:
                    break

        return channel_hop_for_interface

    def __stop_channel_hop(self) -> None:
        if self.__is_channel_hopping():
            self.channel_hop_process.kill()
            self.channel_hop_process.join()

    def __is_channel_hopping(self) -> bool:
        return self.channel_hop_process.is_alive()

    def stop_processes(self) -> None:
        self.stop_monitoring()
