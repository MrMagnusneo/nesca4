/* nesca4-gui: globals from externData.h not defined in nesca_3.cpp.
 * One per line so colliding ones can be toggled individually. */
#include "externData.h"

QJsonArray * jsonArr;
unsigned long long gTargetsNumber;
long long unsigned int gTargets;
std::atomic<int> cons;
std::atomic<int> BrutingThrds;
std::atomic<int> gThreads;
char **loginLst;
char **passLst;
char **wfLoginLst;
char **wfPassLst;
char **ftpLoginLst;
char **ftpPassLst;
char **sshlpLst;
// dup: bool trackerOK;
// dup: bool globalScanFlag;
// dup: bool MapWidgetOpened;
// dup: bool widgetIsHidden;
// dup: bool gNegDebugMode;
// dup: bool gDebugMode;
bool horLineFlag;
bool gPingNScan;
bool gShuffle;
// dup: bool BALogSwitched;
int found;
int indexIP;
int gMode;
int MaxPass;
int MaxLogin;
int MaxWFLogin;
int MaxWFPass;
int MaxFTPLogin;
int MaxFTPPass;
int MaxSSHPass;
int gMaxBrutingThreads;
int gTimeOut;
int PieCamerasC1;
int PieOther;
int PieBA;
int PieSSH;
int camerasC1;
int filtered;
int Overl;
int Alive;
int saved;
int other;
int baCount;
int ssh;
// dup: int globalPinger;
int gPingTimeout;
int cIndex;
unsigned int Activity;
// dup: char trcSrv[256];
// dup: char trcScr[256];
// dup: char trcProxy[128];
// dup: char trcPersKey[64];
// dup: char trcPort[32];
// dup: char trcSrvPortLine[32];
char gTLD[128];
char gPorts[65536];
// dup: char gProxyIP[64];
// dup: char gProxyPort[8];
char currentIP[MAX_ADDR_LEN];
char finalIP[32];
// dup: char gVER[32];

#include "MainStarter.h"
#include "Threader.h"
#include "HikvisionLogin.h"
bool MainStarter::savingBackUpFile = false;
int Threader::gThreadDelay = 0;
bool HikVis::isInitialized = false;
int HikVis::hikCounter=0, HikVis::rviCounter=0, HikVis::hikPart=0, HikVis::rviPart=0;
