# nesca4 for Windows (work in progress)

This branch starts the Windows port. It is **not** a finished
`nesca4.exe`. See `PORTING.md` for the full roadmap and the exact
Linux -> Npcap/Winsock work that remains.

## What is here (milestone 1)

- `wsock.c` — a native Winsock implementation of the four libncsnet
  socket primitives the app-layer checks and bruteforce use
  (`sock_session`, `sock_probe`, `sock_recv`, `sock_util_timeoutns`;
  `sock_send` is `send`). This is the TCP-connect surface only.
- `.github/workflows/build.yml` — CI with a Linux job (full build +
  tests + Qt GUI, verified) and a Windows MSYS2/MinGW64 job that compiles
  the Winsock shim and the pure application/brute objects.

## What is NOT here yet

- The raw-packet engine (SYN/ACK/FIN/window/maimon scans, ICMP ping, ARP)
  needs Npcap on Windows; libncsnet's Linux `AF_PACKET`/netlink layer must
  be ported to `pcap_sendpacket` / `iphlpapi`. See `PORTING.md`.
- Full-functionality + a single self-contained exe requires bundling
  Npcap, which needs an **Npcap OEM license**.

## Note on verifiability

None of the Windows code in this branch could be compiled or tested in
the environment where it was authored (no MinGW/Windows/Npcap). The
Windows CI job is where it actually gets built; expect to iterate on the
first runs.
