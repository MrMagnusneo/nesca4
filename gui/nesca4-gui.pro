# nesca4-gui — reuses the original nesca_3.ui, wired to the nesca4 engine.
QT       += widgets
CONFIG   += c++17
TEMPLATE  = app
TARGET    = nesca4-gui

SOURCES  += main.cpp mainwindow.cpp
HEADERS  += mainwindow.h
FORMS    += nesca_3.ui
RESOURCES += nesca_3.qrc
