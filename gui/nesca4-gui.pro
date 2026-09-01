# nesca4-gui — Qt5 desktop frontend for the nesca4 scanner.
#
# Build (requires Qt5 Widgets on the build machine):
#   cd gui && qmake && make
# Run (expects the nesca4 binary; set it in the UI or place it alongside):
#   ./nesca4-gui

QT       += widgets
# Requires Qt 5.14+ (uses Qt::SkipEmptyParts).
CONFIG   += c++17
TEMPLATE  = app
TARGET    = nesca4-gui

SOURCES  += main.cpp mainwindow.cpp
HEADERS  += mainwindow.h
