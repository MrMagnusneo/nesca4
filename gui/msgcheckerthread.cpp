/* nesca4-gui: MSGCheckerThread stub (server message-of-the-day fetch is
 * a legacy network feature, not used by the nesca4 engine). */
#include "msgcheckerthread.h"

void MSGCheckerThread::doEmitionShowNewMsg(QString str) { emit mct->showNewMsg(str); }
void MSGCheckerThread::run() { /* disabled */ }
