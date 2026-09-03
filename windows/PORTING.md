# nesca4 — Windows port roadmap

**Goal (per requirements):** a native Win64 `nesca4.exe`, no POSIX
emulation DLLs, full functionality (including SYN/raw scanning via
Npcap).

**Status:** NOT complete. This branch provides the application-layer
(TCP-connect) Winsock surface + CI scaffolding + this roadmap. The
raw-packet layer of `libncsnet` still has to be ported to Npcap on a
Windows dev machine. None of the Windows build can be compiled or tested
in the environment where this was authored (no MinGW / Windows / Npcap).

## Why the raw layer is the hard part

Windows (client SKUs) forbids sending TCP over raw sockets, and blocks
raw-socket send entirely for many cases — see Microsoft's TCP/IP raw
sockets limitations. Full scanning therefore requires **Npcap** (or a
signed kernel driver). So SYN/ACK/FIN/window/maimon scans, ICMP ping and
ARP must go through the Npcap send/capture API instead of Linux
`AF_PACKET` + netlink.

## What already ports cleanly (in this branch)

The detection + bruteforce that this project added run on plain TCP:
`sock_session` (connect + banner), `sock_probe`/`sock_recv`/`sock_send`.
`windows/wsock.c` reimplements exactly these four on Winsock. The auth
modules themselves (`nescartsp`, `nescaipc`, `nescarvi`, `nescawf`,
`nescasmtp`, `nescafp`, `nescaneg`) are pure C++/TCP and compile as-is
once the socket primitives resolve. `md5`, `base64`, `hex`, `find_word`
in libncsnet are pure C and compile under MinGW/MSVC.

## Per-file work still required (Linux -> Npcap/Winsock)

libncsnet raw/networking layer (its platform code, currently Linux-only):

| libncsnet file(s) | Linux API used | Windows replacement |
|---|---|---|
| `src/eth/eth.c` | `AF_PACKET`, `SOCK_RAW` | `pcap_open_live` + `pcap_sendpacket` (Npcap) |
| `src/raw/*` | raw `sendto` | `pcap_sendpacket` |
| `src/route/route_open.c` | netlink `RTM_GETROUTE` | `GetIpForwardTable2` (iphlpapi) |
| `src/intf/intf_get.c`, `intf_loop.c` | `SIOCGIFADDR` ioctl / netlink | `GetAdaptersAddresses` (iphlpapi) |
| `src/utils/get_local_mac.c` | `/sys` or ioctl | `GetAdaptersAddresses` |
| `src/trace/linuxread.c` | `AF_PACKET` recv | `pcap_next_ex` |
| ICMP/IGMP/ARP send | raw sockets | `pcap_sendpacket` |

nesca4 own sources needing `#ifdef _WIN32` guards:

| File | POSIX bit | Windows path |
|---|---|---|
| `nescabrute.cc` | `<net/if.h>` (unused on the brute path) | drop under `_WIN32` |
| `nescahik.cc` | `dlopen`/`dlsym` for HCNetSDK | `LoadLibraryA`/`GetProcAddress` (HCNetSDK.dll is native on Windows — this path gets *better*) |
| `nescassh.cc` | libssh | libssh has Windows builds; link the Win64 import lib |
| various | `sys/select.h`, `arpa/inet.h`, `unistd.h`, `close()` | `<winsock2.h>`, `closesocket` (via a `compat.h`) |

## Build system

- **Toolchain:** MinGW-w64 (MSYS2 `mingw-w64-x86_64` toolchain) — produces
  a native PE Win64 exe. Static-link libstdc++/libgcc/libwinpthread
  (`-static -static-libgcc -static-libstdc++`) so there is no runtime
  POSIX/DLL dependency, satisfying "native Win64 EXE, no POSIX DLL".
  (MSVC can't drive the autoconf project without a rewrite of the build.)
- **Npcap:** link against the Npcap SDK (`wpcap.lib`/`Packet.lib`,
  `-lwpcap`), ship the Npcap runtime via its installer. Bundling Npcap
  inside your own installer requires an **Npcap OEM license** — the free
  redistribution terms do not permit silent/bundled install.
- **Deps for full functionality:** `iphlpapi`, `ws2_32`, `wpcap`.

## Suggested milestones

1. **M1 (this branch):** Winsock socket layer + CI that compiles the
   application/brute objects. Verifies the TCP surface builds on Windows.
2. **M2:** guard nesca4's POSIX includes; port `nescahik` dlopen ->
   LoadLibrary; get a connect-scan-only `nesca4.exe` linking (no Npcap).
   *(Note: connect-scan-only was rejected as the final goal, but it is the
   natural intermediate that proves the non-raw engine on Windows.)*
3. **M3:** port the libncsnet raw layer to Npcap (table above), add the
   Npcap SDK to the build, wire SYN/ACK/etc. through `pcap_sendpacket`.
4. **M4:** installer bundling Npcap OEM (requires the OEM license).

Milestones 3–4 are the bulk of the effort and must be done and tested on
a Windows machine with the Npcap SDK.
