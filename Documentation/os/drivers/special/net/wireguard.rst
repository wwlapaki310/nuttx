========================
WireGuard Device Driver
========================

WireGuard is a VPN that runs the Noise_IKpsk2 handshake and carries
transport data as ChaCha20-Poly1305 over UDP. NuttX implements it as a
virtual network device (``wg0``): packets the routing table sends to
``wg0`` are encrypted and forwarded as UDP datagrams to the configured
peer, and UDP datagrams received on the listen port are decrypted and
delivered to the network stack as though they had arrived on ``wg0``. The
peer can be any WireGuard implementation (the Linux kernel module,
``wireguard-go``, ``boringtun``, another NuttX, ...).

-  **Driver**: ``drivers/net/wireguard/``

   -  ``wireguard.c`` — the ``netdev_lowerhalf`` device: a UDP socket, a
      receive thread, the timer state machine, and the ioctl handlers.
   -  ``wg_noise.c`` — the protocol core (handshake, key derivation,
      anti-replay window, cookie / mac2 under load). Derived from
      `wireguard-lwip <https://github.com/smartalock/wireguard-lwip>`_
      (BSD-3-Clause), which is why the device depends on
      ``ALLOW_BSD_COMPONENTS``.
   -  ``wg_crypto.c`` — a thin layer over NuttX's own ``crypto/``
      primitives (BLAKE2s, ChaCha20-Poly1305, Curve25519).

-  **ABI**: ``include/nuttx/net/wireguard.h`` defines the fixed-size,
   pointer-free structures exchanged with the driver, and
   ``include/nuttx/net/ioctl.h`` the ioctl command numbers. The header is
   shared verbatim by the kernel driver and by the user-space ``wg``
   command, so it holds no pointers: in ``PROTECTED`` and ``KERNEL``
   builds the driver copies these structures directly to and from the
   caller.

The device is a ``NET_LL_TUN`` link type (no link-layer header; the tunnel
carries bare IP packets). Only IPv4 is supported for now.

Configuration Options
=====================

``CONFIG_NET_WIREGUARD``
  Enable the WireGuard virtual network device. Requires ``NET_UDP``,
  ``NET_IPv4`` and ``ALLOW_BSD_COMPONENTS``, and a real random source —
  either the entropy pool (``CRYPTO_RANDOM_POOL``) or a hardware RNG
  behind ``/dev/urandom`` (``DEV_URANDOM_ARCH``). The constant-seeded
  software PRNGs are refused, because with them every device would
  generate the same keys on every boot. Selecting it pulls in
  ``NETDEV_IOCTL`` and ``CRYPTO_CURVE25519``.
``CONFIG_NET_WIREGUARD_NINTERFACES``
  How many ``wgN`` devices to register at start-up (default 1).
``CONFIG_NET_WIREGUARD_MAX_PEERS``
  Peers allocated statically inside each device (default 1). Each peer
  costs roughly 1 KiB plus three anti-replay windows.
``CONFIG_NET_WIREGUARD_MAX_AIPS``
  Allowed-ips (cryptokey-routing prefixes) per peer (default 2).
``CONFIG_NET_WIREGUARD_PKTSIZE``
  MTU of the IP packets carried inside the tunnel (default 1420, leaving
  room for the WireGuard, UDP and outer IPv4 headers within a 1500-byte
  Ethernet frame).
``CONFIG_NET_WIREGUARD_REPLAY_WINDOW``
  Anti-replay window in packets (default 2048, must be a multiple of 64).
  Data packets more than this many counters behind the newest seen are
  dropped.
``CONFIG_NET_WIREGUARD_LOAD_THRESHOLD``
  Handshake initiations per second above which the device answers
  initiations that carry no valid mac2 with a cookie reply instead of
  doing the Diffie-Hellman work (WireGuard whitepaper 5.4.7).
``CONFIG_NET_WIREGUARD_RXSTACKSIZE`` / ``CONFIG_NET_WIREGUARD_RXPRIORITY``
  Stack size and priority of the receive thread.

Time Requirements
=================

Before this device initiates handshakes, the platform must restore
``CLOCK_REALTIME`` from a reliable RTC or another trusted time source.
WireGuard's responder requires initiation timestamps to increase for the
same peer key. A fixed build-time start date is not sufficient across
reboots; merely enabling ``CONFIG_RTC`` does not prove that the RTC is set.

``wg_tai64n.c`` rounds realtime to tick resolution and keeps a shared
in-memory high-water mark, so equal clock readings, same-boot clock rollback,
and interface/key reconfiguration do not produce decreasing timestamps.
Clock acquisition errors abort initiation rather than falling back to
uptime. Protocol retry and expiration timers still use monotonic time.

The high-water mark is not persistent. A clock reset or rollback across a
reboot can therefore prevent reconnection with the same key until realtime
exceeds the timestamp remembered by the remote peer. Platforms without a
retained clock or trusted time synchronization need an additional persistent
timestamp design; that support is not implemented here.

Key Lifetime
============

Bringing the interface down destroys every session: ``wg_ifdown`` clears all
three key pairs and the in-progress handshake of each peer, so the transport
keys that carried traffic do not outlive the tunnel. Handshake state is
shorter-lived still — ``wg_start_session`` wipes it, and its own working copy
of the derived key pair, as soon as the transport keys exist.

The static private key deliberately **survives** a down, so that ``wg up``
works again without reconfiguring the interface; the same is true of the
values derived from the static identity alone (the peer's static-static
Diffie-Hellman result and the MAC/cookie labels). Callers that need the
identity gone as well must change or clear the private key explicitly, which
also means erasing the configuration file if one is in use.

Runtime Configuration
=====================

The device registers with no key and no peers; everything is set at run
time through the ioctls declared in ``include/nuttx/net/wireguard.h``.
Nothing is baked into the image. The five commands, on any ``AF_INET``
socket, are:

``SIOCSWGIF`` / ``SIOCGWGIF`` (``struct wg_ifreq_s``)
  Set / get the interface: private key, listen port, tunnel address and
  netmask, and the up/down state. The private key is **write-only** — it
  is accepted by ``SIOCSWGIF`` and is never copied back by ``SIOCGWGIF``,
  so key material does not leave the kernel once set. ``SIOCGWGIF``
  returns the derived public key instead.
``SIOCSWGPEER`` / ``SIOCDWGPEER`` / ``SIOCGWGPEER`` (``struct wg_peerreq_s``)
  Add or update / delete / enumerate a peer. Set and delete address the
  peer by public key; get enumerates by ``index`` (``0 .. npeers-1``) and
  fills in the endpoint, allowed-ips, keepalive and the get-only
  statistics (last handshake, rx/tx bytes).

These are normally driven by the ``wg`` command from ``apps/system/wg``
rather than called directly.

The private key and listen port may only be changed while the interface
is down; peers and their endpoints may be changed at any time.

Example
=======

.. code-block:: c

  #include <sys/ioctl.h>
  #include <nuttx/net/wireguard.h>

  int s = socket(AF_INET, SOCK_DGRAM, 0);
  struct wg_ifreq_s ifr;

  memset(&ifr, 0, sizeof(ifr));
  strlcpy(ifr.ifname, "wg0", IFNAMSIZ);

  /* Private key, listen port and tunnel address, then bring it up. */

  memcpy(ifr.private_key, privkey, WG_KEY_LEN);
  ifr.listen_port = 51820;
  ifr.addr.s_addr = HTONL(0x0a0a0002);      /* 10.10.0.2 */
  ifr.netmask.s_addr = HTONL(0xffffff00);
  ifr.flags = WG_IF_HAS_PRIVATE_KEY | WG_IF_HAS_LISTEN_PORT |
              WG_IF_HAS_ADDR | WG_IF_UP;
  ioctl(s, SIOCSWGIF, &ifr);

  /* Add a peer with an endpoint and one allowed-ips prefix. */

  struct wg_peerreq_s peer;
  memset(&peer, 0, sizeof(peer));
  strlcpy(peer.ifname, "wg0", IFNAMSIZ);
  memcpy(peer.public_key, peerpub, WG_KEY_LEN);
  peer.endpoint.sin_family = AF_INET;
  peer.endpoint.sin_port = HTONS(51820);
  peer.endpoint.sin_addr.s_addr = HTONL(0xc0a80105);   /* 192.168.1.5 */
  peer.aips[0].addr.s_addr = HTONL(0x0a0a0001);        /* 10.10.0.1/32 */
  peer.aips[0].cidr = 32;
  peer.naips = 1;
  peer.flags = WG_PEER_HAS_ENDPOINT | WG_PEER_HAS_AIPS;
  ioctl(s, SIOCSWGPEER, &peer);

  close(s);
