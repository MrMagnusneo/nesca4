# nesca4-gui — Qt5 desktop frontend for the nesca4 scanner.
# Build (requires Qt 5.14+ Widgets):  qmake && make
QT       += widgets
# Requires Qt 5.14+ (uses Qt::SkipEmptyParts).
CONFIG   += c++17
TEMPLATE  = app
TARGET    = nesca4-gui

SOURCES  += main.cpp mainwindow.cpp activitygraph.cpp
HEADERS  += mainwindow.h activitygraph.h
