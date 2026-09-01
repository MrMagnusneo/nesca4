# nesca4-gui

A Qt5 desktop frontend for the nesca4 scanner, in the spirit of the old
nesca GUI. It drives the `nesca4` command-line engine as a subprocess
(`QProcess`): you fill in target / ports / services / options, it runs
`nesca4`, streams its output live into a console, and loads nesca4's own
HTML report into a second tab when the scan finishes.

## Why a wrapper (and not a rewrite)

nesca4 is a self-contained CLI engine built on libncsnet. Wrapping it
keeps the engine and the UI decoupled: the GUI needs no changes to the
engine, and the engine stays testable on its own. The GUI simply builds
the argument list, runs the binary, and renders its output + `-html`
report.

## Build

Requires **Qt 5.14+** (Widgets). From this directory:

```
qmake
make
```

This produces `nesca4-gui`. (Qt is not bundled with the repo; install
your distro's `qtbase5-dev` / `qt5-qtbase-devel` or the official Qt SDK.)

## Run

```
./nesca4-gui
```

Set the path to the `nesca4` binary at the top of the window (defaults to
`./nesca4`), enter a target, optionally ports/services/options, and press
*Start scan*. Raw-socket port scans still require the usual privileges
(run as root / grant `CAP_NET_RAW`), exactly as for the CLI.

## Services

The **Services** field maps to nesca4's `-s`, e.g.:

```
http:80,ftp:21,rtsp:554,ssh:22,rvi:37777,ipc:80,wf:8080,smtp:25,hik:8000
```

## Note

This GUI was written against the Qt5 API but could not be compiled in the
environment where it was authored (no Qt available there). Build it on a
machine with Qt5 installed; if your Qt is older than 5.14, replace
`Qt::SkipEmptyParts` in `mainwindow.cpp` with `QString::SkipEmptyParts`.
