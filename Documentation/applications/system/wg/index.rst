===================================
``wg`` WireGuard Configuration Tool
===================================

``wg`` configures the WireGuard virtual network device (``wg0``, see
:doc:`/os/drivers/special/net/wireguard`) at run time over the
device's ioctl ABI. It is a small, self-contained subset of the upstream
``wg(8)`` command: it sets the private key, listen port and tunnel
address, adds and removes peers, brings the interface up and down, and
reads and writes ``wg(8)``-format configuration files.

Configuration
=============

Enable ``CONFIG_SYSTEM_WG`` (it depends on ``CONFIG_NET_WIREGUARD``).

- ``CONFIG_SYSTEM_WG_CONFIG_PATH``: default path used by ``saveconf`` and
  ``setconf`` when no file is given (for example ``/data/wg0.conf``).
  Point it at a writable, persistent file system so a configuration
  survives a reboot.

Usage
=====

::

  wg [up|down|show|showconf|setconf|saveconf|genkey|pubkey|set]

- ``up`` — bring ``wg0`` up (the default when no argument is given). The
  private key must already be set.
- ``down`` — take ``wg0`` down.
- ``show`` — print interface and peer status (public key, listen port,
  endpoints, allowed-ips, last handshake, transfer counters).
- ``showconf`` — print the current configuration in ``wg(8)`` format.
- ``saveconf [file]`` — write the configuration to a file so it survives a
  reboot (defaults to ``CONFIG_SYSTEM_WG_CONFIG_PATH``).
- ``setconf <file>`` — load a ``wg(8)``-format configuration file.
- ``genkey`` — print a new Curve25519 private key.
- ``pubkey`` — read a private key from stdin and print the matching public
  key.
- ``set <item> ...`` — change one setting:

  ::

    set private-key <key>
    set listen-port <port>
    set address <addr>/<prefix>
    set peer <public-key> [endpoint <addr:port>]
                          [allowed-ips <addr>/<prefix>[,...]]
                          [persistent-keepalive <seconds>|off]
                          [preshared-key <key>]
    set peer <public-key> remove

The private key, the listen port and ``setconf`` are accepted only while
``wg0`` is down.

Keys and the configuration file
===============================

The driver never returns the private key (it is write-only in the ABI),
so ``wg`` keeps the private key in the configuration file as the source of
truth: ``set private-key`` records it there as well as pushing it to the
device, and ``saveconf`` writes the file from that record plus the state
read back from the device. ``genkey`` and ``pubkey`` run entirely in user
space (a vendored MIT Curve25519), so a key pair can be produced before
any interface exists and ``pubkey`` agrees with the host ``wg(8)``.

Example
=======

::

  nsh> wg genkey
  cO...=                         # a new private key
  nsh> wg set private-key cO...=
  nsh> wg set listen-port 51820
  nsh> wg set address 10.10.0.2/24
  nsh> wg set peer <peer-public-key> \
         endpoint 192.168.1.5:51820 \
         allowed-ips 10.10.0.1/32 \
         persistent-keepalive 25
  nsh> wg up
  nsh> wg show
  nsh> wg saveconf /data/wg0.conf
