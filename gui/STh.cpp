#include "STh.h"
#include <QProcess>
#include <QFileInfo>
#include <QDir>
#include <QCoreApplication>
#include <QRegExp>
#include <cstring>

//BA TablelistView
void STh::doEmitionChangeBARow(int index, QString loginPass, QString percentage)
{
	emit stt->signalChangeBARow(index, loginPass, percentage);
}

void STh::doEmitionShowRedVersion()
{
	emit stt->showRedVersion();	
}
void STh::doEmitionStartScanIP()
{
	emit stt->startScanIP();	
}
void STh::doEmitionStartScanDNS()
{
	emit stt->startScanDNS();		
}
void STh::doEmitionStartScanImport()
{
	emit stt->startScanImport();		
}
void STh::doEmitionAddIncData(QString(ip), QString str)
{
	emit stt->sIncData(ip, str);
}
void STh::doEmitionAddOutData( QString str)
{
	emit stt->sOutData(str);
}
void STh::doEmitionFoundData(QString str)
{
	emit stt->changeFoundData(str);
}

void STh::doEmitionRedFoundData(QString str)
{
	emit stt->changeRedFoundData(str);
}
void STh::doEmitionGreenFoundData(QString str)
{
	emit stt->changeGreenFoundData(str);
}
void STh::doEmitionFoundDataCustom(QString str, QString color)
{
	emit stt->foundDataCustom(str, color);
}
void STh::doEmitionYellowFoundData(QString str)
{
	emit stt->changeYellowFoundData(str);
}
void STh::doEmitionDebugFoundData(QString str)
{
	emit stt->changeDebugFoundData(str);
}
void STh::doEmitionKillSttThread()
{
	emit stt->killSttThread();	
}
void STh::doEmitionDataSaved(bool status)
{
    emit stt->signalDataSaved(status);
}
void STh::doEmitionUpdateArc(unsigned long gTargets)
{
	emit stt->signalUpdateArc(gTargets);
}
void STh::doEmitionBlockButton(bool value)
{
	emit stt->signalBlockButton(value);
}

void STh::setMode(short mode) {
	gMode = mode;
}
void STh::setTarget(QString target) {
	this->target = target;
}
void STh::setPorts(QString ports) {
	this->ports = ports;
}
/* map an nesca4 output line to the nesca GUI signal hub + drawer globals */
static void ncsEmit(const QString &raw)
{
	QString line=raw; while(line.endsWith('\r')) line.chop(1);
	if (line.trimmed().isEmpty()) return;
	Activity += (unsigned)line.size();          /* drives activity graph */
	QString low=line.toLower();

	if (line.startsWith("Report nesca4 for")) {
		QString ip=line.section(' ',3,3);
		strncpy(currentIP, ip.toLocal8Bit().constData(), MAX_ADDR_LEN-1);
		++found; ++Alive; ++gTargets;
		STh::doEmitionUpdateArc(gTargets);
		STh::doEmitionGreenFoundData(line);
		return;
	}
	bool hit=low.contains("(passwd)")||low.contains(" pass:");
	if (hit){ ++PieBA; ++baCount; ++saved; STh::doEmitionFoundData(line); STh::doEmitionDataSaved(true); return; }
	if (low.contains("rtsp(")||low.contains("hikvision(")||low.contains("ipc(")||low.contains("rvi(")){
		++PieCamerasC1; ++camerasC1; STh::doEmitionFoundData(line); return; }
	if (low.contains("ssh(")){ ++PieSSH; ++ssh; STh::doEmitionFoundData(line); return; }
	if (line.startsWith("  ")){ STh::doEmitionFoundData(line); return; }
	if (low.contains("err")||low.contains("fail")||low.contains("unavailable")
	    ||low.contains("could not")||low.contains("unable")){ ++PieOther; ++other; ++filtered;
		STh::doEmitionRedFoundData(line); return; }
	if (low.contains("running nesca4")||low.contains("up ips")||low.contains("success")){
		STh::doEmitionGreenFoundData(line); return; }
	STh::doEmitionAddOutData(line);
}

static QString ncsServices(const QString &ports)
{
	QStringList out;
	const auto toks=ports.split(QRegExp("[ ,]"), QString::SkipEmptyParts);
	for (QString t : toks){ t=t.section(':',-1); bool ok=false; int p=t.toInt(&ok); if(!ok) continue;
		const char *s=(p==21)?"ftp":(p==22)?"ssh":(p==25)?"smtp":(p==554)?"rtsp":
			(p==8000)?"hik":(p==37777)?"rvi":"http";
		out<<QString("%1:%2").arg(s).arg(p); }
	return out.join(",");
}

void STh::run()
{
	/* locate the nesca4 engine next to the gui, or in the parent dir */
	QString bin=QCoreApplication::applicationDirPath()+"/nesca4";
	if (!QFileInfo::exists(bin)) bin=QCoreApplication::applicationDirPath()+"/../nesca4";
	if (!QFileInfo::exists(bin)) bin="./nesca4";

	QStringList args;
	args<<this->target.split(' ', QString::SkipEmptyParts);
	if (!this->ports.isEmpty()){ args<<"-p"<<this->ports; args<<"-s"<<ncsServices(this->ports); }
	if (gMaxBrutingThreads>0) args<<"-threads-brute"<<QString::number(gMaxBrutingThreads);
	if (gTimeOut>0) args<<"-wait-scan"<<(QString::number(gTimeOut)+"s");
	args<<"-v";

	globalScanFlag=true;
	QProcess p;
	p.setWorkingDirectory(QFileInfo(bin).absolutePath());
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.start(bin, args);
	if (!p.waitForStarted(4000)){
		doEmitionRedFoundData("Could not start nesca4 engine ("+bin+"). Build it first.");
		doEmitionBlockButton(false); doEmitionKillSttThread(); globalScanFlag=false; return;
	}
	doEmitionGreenFoundData("[*] nesca4 "+args.join(' '));

	QByteArray buf;
	while (p.state()!=QProcess::NotRunning){
		if (!globalScanFlag){ p.terminate(); if(!p.waitForFinished(1500)) p.kill(); break; }
		if (p.waitForReadyRead(200)){
			buf+=p.readAll();
			int nl;
			while ((nl=buf.indexOf('\n'))>=0){
				ncsEmit(QString::fromLocal8Bit(buf.left(nl))); buf.remove(0,nl+1);
			}
		}
	}
	p.waitForFinished(800);
	buf+=p.readAll();
	for (const QByteArray &l : buf.split('\n')) ncsEmit(QString::fromLocal8Bit(l));

	doEmitionYellowFoundData("[*] scan finished.");
	doEmitionBlockButton(false);
	doEmitionKillSttThread();
	globalScanFlag=false;
}
