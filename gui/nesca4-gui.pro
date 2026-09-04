# nesca4-gui — the original nesca 3 GUI, wired to the nesca4 CLI engine.
QT       += core gui widgets network
CONFIG   += c++11
QMAKE_CXXFLAGS += -fpermissive -Wno-narrowing -Wno-write-strings -Wno-deprecated-declarations -Wno-unused-parameter
TARGET    = nesca4-gui
TEMPLATE  = app
SOURCES  += ActivityDrawerTh_HorNet.cpp base64.cpp CheckKey_Th.cpp DrawerTh_GridQoSScanner.cpp DrawerTh_HorNet.cpp DrawerTh_ME2Scanner.cpp DrawerTh_QoSScanner.cpp DrawerTh_VoiceScanner.cpp globals.cpp main.cpp msgcheckerthread.cpp nesca_3.cpp piestat.cpp progressbardrawer.cpp STh.cpp Utils.cpp vercheckerthread.cpp 
HEADERS  += ActivityDrawerTh_HorNet.h base64.h CheckKey_Th.h DrawerTh_GridQoSScanner.h DrawerTh_HorNet.h DrawerTh_ME2Scanner.h DrawerTh_QoSScanner.h DrawerTh_VoiceScanner.h externData.h externFunctions.h HikvisionLogin.h mainResources.h MainStarter.h msgcheckerthread.h nesca_3.h piestat.h progressbardrawer.h resource.h STh.h Threader.h ui_nesca_3.h Utils.h vercheckerthread.h 
FORMS    += nesca_3.ui
RESOURCES += nesca_3.qrc
