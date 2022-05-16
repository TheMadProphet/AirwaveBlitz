# Interface

**Wireless network interface controller** (or just **interface**) is, simply put, a tool that allows wireless
communication with other devices ([wiki](https://en.wikipedia.org/wiki/Wireless_network_interface_controller)). Since
the main theme of AB is gathering wireless traffic and sending out custom wireless requests, it should be of no surprise
that interface is required in almost every part of this application. Therefore, knowing how to manipulate it manually
might become vital during development.

## Heads up

AB is not the only software that will try to take control of an interface. Usually, interfaces are used by different
kinds of programs (such as network managers, to connect to a wi-fi). This means that AB can not have full
control of interface while these programs are running, and this may lead to several issues during runtime.

As a work-around, while testing, it is advised to kill all the processes that might be using interface. This can be done
using `airmon-ng`.

```shell
sudo airmon-ng check # Lists processes that use interface
sudo airmon-ng check kill # Automatically kills above processes
```

This command will also turn off NetworkManager service (responsible for connecting to wi-fi). So, to be able to connect
to wi-fi again, run the following command.

```shell
sudo service NetworkManager start
```

## Interface Management

Most of the interface management can be done using `iw` and `ip` commands (same commands that are used by AB).

### List Interfaces

```shell
sudo iw dev
```

### Display Interface Info

```shell
sudo iw dev <iface> info
sudo ip link show <iface>
```

### State

Interface can be in **up** or **down** state. Can be thought of as an on/off state for interface.

```shell
sudo iw dev set <iface> up
sudo iw dev set <iface> down
```

### Mode

There are eight modes available for interfaces, however we are currently interested in two:

- **Managed** (aka **client**, or **station**) - The *default* state of interface. Allows scanning and connecting to
  APs.
- **Monitor** - State that allows interface to monitor all traffic received on a wireless channel.
  ([wiki](https://en.wikipedia.org/wiki/Monitor_mode))

```shell
sudo ip link set <iface> down # Need to turn off interface before changing mode
sudo iw dev <iface> set type monitor # Or "managed"
sudo ip link set <iface> up # Turn interface back on
```

### Mac

MAC address is a unique identifier assigned to interface ([wiki](https://en.wikipedia.org/wiki/MAC_address)). It is
used as a network address, a way to tell the source and destination of a packet when communicating in local network.
MAC address can be changed (called [MAC Spoofing](https://en.wikipedia.org/wiki/MAC_spoofing)) using following commands.

**Warning:** Make sure to write down original MAC address before spoofing it.
```shell

```
### Name(?)