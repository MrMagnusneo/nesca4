/* nesca4-gui — faithful nesca-3 style main window. */
#include "mainwindow.h"
#include "activitygraph.h"

#include <QLineEdit>
#include <QTextBrowser>
#include <QLabel>
#include <QPushButton>
#include <QProcess>
#include <QTimer>
#include <QFont>
#include <QMouseEvent>
#include <QFile>
#include <QDir>
#include <QFileInfo>
#include <QDateTime>
#include <QScrollBar>
#include <QRegularExpression>
#include <QTextCursor>
#include <QApplication>

/* ---- nesca palette ---- */
#define BG      "#1a1a1a"
#define TXT     "#d8d8d8"
#define DIM     "#6a6a6a"
#define GREEN   "#00b304"
#define GREENH  "#1efd00"
#define ORANGE  "#faaa3c"
#define GOLD    "#d1a000"
#define LINK    "#3aa0ff"
#define REDc    "#d84a3c"
#define PORTSc  "#5a9bd4"

static QFont euro(int pt, bool bold=false)
{
	QFont f("Eurostile");
	f.setPointSize(pt);
	f.setBold(bold);
	return f;
}

MainWindow::MainWindow(QWidget *parent)
	: QWidget(parent), proc(nullptr), bytesTotal(0),
	  foundTargets(0), bruteHits(0), offlineCount(0), savedCount(0),
	  progressPct(0)
{
	setWindowFlags(Qt::FramelessWindowHint);
	setFixedSize(500, 800);
	setStyleSheet(
		"QWidget{background-color:" BG ";color:" TXT ";}"
		"QLineEdit{background-color:#0e0e0e;color:#d8d8d8;border:1px solid #4a4a4a;"
		"  selection-background-color:" ORANGE ";}"
		"QLineEdit:focus{border:1px solid " ORANGE ";}"
		"QPushButton{background-color:qlineargradient(x1:1,y1:0,x2:1,y2:1,"
		"  stop:0.68 rgba(0,0,0,250),stop:1 rgba(255,255,255,120));"
		"  color:" GREEN ";border:1px solid #4a4a4a;}"
		"QPushButton:hover{color:" GREENH ";}"
		"QTextBrowser{background-color:#0a0a0a;color:#d8d8d8;border:1px solid #4a4a4a;}"
		"QScrollBar:vertical{background:#1a1a1a;width:12px;border:1px solid #3a3a3a;}"
		"QScrollBar::handle:vertical{background:#3a3a3a;}"
	);

	/* ===== title bar ===== */
	L("NESCA 4  ::  Revealing the Unseen Horizon", 60, 10, 380, 20,
		TXT, 11, true, 1);
	QPushButton *mn=B("_", 452, 8, 20, 18); connect(mn,&QPushButton::clicked,this,&QWidget::showMinimized);
	QPushButton *cl=B("X", 474, 8, 20, 18); connect(cl,&QPushButton::clicked,qApp,&QApplication::quit);
	{ QLabel *g=L("▓▓▓", 470, 0, 30, 8, REDc, 6); g->setStyleSheet("color:" REDc ";background:transparent;"); }

	/* ===== tab row ===== */
	const char *tabs[]={"IP Scan","DNS Scan","Import","NS-Track"};
	for (int i=0;i<4;i++){ QPushButton*t=B(tabs[i], 10+i*72, 34, 70, 18);
		if(i==0) t->setStyleSheet("color:" ORANGE ";border:1px solid " ORANGE ";background:#1a1a1a;"); }
	L(":NS-IRC", 400, 36, 44, 14, DIM, 8, false, 2);
	L(":Dataflow", 446, 36, 48, 14, DIM, 8, false, 2);

	/* ===== inputs ===== */
	L("IP RANGE", 24, 74, 80, 20, TXT, 9);      ipLine=E("", 110, 72, 320, 22);
	ipLine->setPlaceholderText("62.16.0.0/24");
	L("PORTS", 24, 100, 80, 20, TXT, 9);        portsLine=E("80,81,88,8080,8888,21,554,8000,37777", 110, 98, 320, 22);
	L("SERVICES", 24, 126, 80, 20, TXT, 9);     servicesLine=E("http:80,ftp:21,rtsp:554,ssh:22,hik:8000", 110, 124, 320, 22);
	L("THREADS", 24, 152, 80, 20, TXT, 9);      threadsLine=E("200", 110, 150, 60, 22);
	L("TIMEOUT", 210, 152, 70, 20, TXT, 9);     timeoutLine=E("3", 300, 150, 60, 22);
	L("ENGINE", 24, 178, 80, 20, DIM, 8);       engineLine=E("./nesca4", 110, 176, 320, 22);
	startBtn=B("Start", 205, 206, 90, 24);
	connect(startBtn, &QPushButton::clicked, this, &MainWindow::onStartStop);

	/* separator */
	{ QLabel*s=new QLabel(this); s->setGeometry(14,240,472,1); s->setStyleSheet("background:#4a4a4a;"); }

	/* ===== stats (left) ===== */
	int sy=258, dy=19;
	L("Current IP:",   24, sy+0*dy, 90, 16, DIM, 9);   vCurrent=L("--",       118, sy+0*dy, 130, 16, GREENH, 9, true);
	L("Threads:",      24, sy+1*dy, 90, 16, DIM, 9);   vThreads=L("0/0",      118, sy+1*dy, 130, 16, TXT, 9, true);
	L("Brute threads:",24, sy+2*dy, 90, 16, DIM, 9);   vBrute  =L("0",        118, sy+2*dy, 130, 16, TXT, 9, true);
	L("Targets:",      24, sy+3*dy, 90, 16, DIM, 9);   vTargets=L("0 [0.0%]", 118, sy+3*dy, 130, 16, GOLD, 9, true);
	L("IP/s:",         24, sy+4*dy, 90, 16, DIM, 9);   vIps    =L("0/s",      118, sy+4*dy, 130, 16, TXT, 9, true);
	L("Saved/Parsed:", 24, sy+5*dy, 90, 16, DIM, 9);   vSaved  =L("0/0",      118, sy+5*dy, 130, 16, GREENH, 9, true);
	L("Offline:",      24, sy+6*dy, 90, 16, DIM, 9);   vOffline=L("0",        118, sy+6*dy, 130, 16, DIM, 9, true);

	/* ===== oscilloscope (right) ===== */
	const char *modes[]={":ME2 mode",":QoS mode",":Voice mode",":Pie stats"};
	for (int i=0;i<4;i++) L(modes[i], 250+i*60, 250, 60, 12, i==0?ORANGE:DIM, 7, false, 1);
	graph=new ActivityGraph(this); graph->setGeometry(250, 264, 236, 96);
	{ QLabel*b=new QLabel(this); b->setGeometry(250,264,236,96);
	  b->setStyleSheet("background:transparent;border:1px solid #4a4a4a;"); b->raise(); }

	/* ===== category legend ===== */
	struct{const char*n;const char*c;int col;int row;QLabel**v;}
	cats[]={
		{"Cameras",   REDc,   0,0,&cCameras},{"Bad req",  "#a04040",1,0,&cBads},
		{"Basic Auth",LINK,   0,1,&cBasic},  {"Other",    "#3ad0d0",1,1,&cOther},
		{"Overloads", GOLD,   0,2,&cOverloads},{"Lowloads","#d060a0",1,2,&cLowloads},
		{"SSH",       "#e0e0e0",0,3,&cSSH},   {"Alive",   GREENH,  1,3,&cAlive},
	};
	int ly=372, ldy=15;
	for (auto &c:cats){
		int x=(c.col==0)?238:372;
		QLabel*dot=new QLabel(this); dot->setGeometry(x, ly+c.row*ldy+3, 7,7);
		dot->setStyleSheet(QString("background:%1;border:none;").arg(c.c));
		*c.v=L(QString("%1: 0").arg(c.n), x+12, ly+c.row*ldy, 120, 13,
			c.c, 8, false, 0);
	}

	/* ===== log ===== */
	log=new QTextBrowser(this); log->setGeometry(18, 446, 464, 300);
	log->setFont(euro(9));
	QPushButton *clr=B("X", 466, 446, 16, 20);
	clr->setStyleSheet("color:" REDc ";border:1px solid #4a4a4a;background:#1a1a1a;");
	connect(clr, &QPushButton::clicked, this, &MainWindow::onClearLog);

	/* ===== bottom status ===== */
	L("Status:", 18, 756, 50, 16, DIM, 9);   statusVal=L("idle", 70, 756, 200, 16, TXT, 9);
	L("Activity:",270, 756, 56, 16, DIM, 9); activityVal=L("0b", 330, 756, 150, 16, TXT, 9);

	sec=new QTimer(this); sec->setInterval(1000);
	connect(sec, &QTimer::timeout, this, &MainWindow::onSecTick);

	log->setHtml(QString("<span style='color:" DIM "'>[*] nesca4-gui ready. "
		"Enter a target and press Start.</span><br>"));
}

MainWindow::~MainWindow()
{
	if (proc && proc->state()!=QProcess::NotRunning){ proc->kill(); proc->waitForFinished(600); }
}

/* ---- widget helpers ---- */
QLabel *MainWindow::L(const QString &t,int x,int y,int w,int h,const char*color,int pt,bool bold,int align)
{
	QLabel *l=new QLabel(t,this); l->setGeometry(x,y,w,h);
	l->setFont(euro(pt,bold));
	l->setStyleSheet(QString("color:%1;background:transparent;").arg(color));
	l->setAlignment(align==1?Qt::AlignCenter:align==2?Qt::AlignRight|Qt::AlignVCenter
		:Qt::AlignLeft|Qt::AlignVCenter);
	return l;
}
QLineEdit *MainWindow::E(const QString &t,int x,int y,int w,int h)
{
	QLineEdit *e=new QLineEdit(t,this); e->setGeometry(x,y,w,h); e->setFont(euro(9)); return e;
}
QPushButton *MainWindow::B(const QString &t,int x,int y,int w,int h)
{
	QPushButton *b=new QPushButton(t,this); b->setGeometry(x,y,w,h); b->setFont(euro(9)); return b;
}

/* ---- frameless drag ---- */
void MainWindow::mousePressEvent(QMouseEvent *e)
{
	if (e->button()==Qt::LeftButton && e->pos().y()<32)
		dragPos = e->globalPos() - frameGeometry().topLeft();
}
void MainWindow::mouseMoveEvent(QMouseEvent *e)
{
	if (e->buttons()&Qt::LeftButton && !dragPos.isNull() && e->pos().y()<600)
		move(e->globalPos() - dragPos);
}

/* ---- engine ---- */
QStringList MainWindow::buildArgs(QString &outReport) const
{
	QStringList a;
	if (!ipLine->text().trimmed().isEmpty())
		a << ipLine->text().trimmed().split(' ', Qt::SkipEmptyParts);
	if (!portsLine->text().trimmed().isEmpty()) a << "-p" << portsLine->text().trimmed();
	if (!servicesLine->text().trimmed().isEmpty()) a << "-s" << servicesLine->text().trimmed();
	a << "-threads-brute" << threadsLine->text().trimmed();
	a << "-wait-scan" << (timeoutLine->text().trimmed()+"s");
	a << "-v";
	outReport = QDir::temp().filePath("nesca4-report-"
		+ QString::number(QDateTime::currentMSecsSinceEpoch()) + ".html");
	a << "-html" << outReport;
	return a;
}

void MainWindow::resetStats()
{
	bytesTotal=0; foundTargets=bruteHits=offlineCount=savedCount=0; progressPct=0;
	vCurrent->setText("--"); vThreads->setText(threadsLine->text()+"/"+threadsLine->text());
	vBrute->setText("0"); vTargets->setText("0 [0.0%]"); vIps->setText("0/s");
	vSaved->setText("0/0"); vOffline->setText("0");
	cCameras->setText("Cameras: 0"); cBasic->setText("Basic Auth: 0");
	cSSH->setText("SSH: 0"); cAlive->setText("Alive: 0");
	cBads->setText("Bad req: 0"); cOther->setText("Other: 0");
	cOverloads->setText("Overloads: 0"); cLowloads->setText("Lowloads: 0");
	activityVal->setText("0b"); graph->reset();
}

void MainWindow::setRunning(bool running)
{
	startBtn->setText(running?"Stop":"Start");
	startBtn->setStyleSheet(running
		?"color:" REDc ";border:1px solid #6a2a2a;"
		:"");
	ipLine->setEnabled(!running); graph->setActive(running);
	statusVal->setText(running?"Scanning...":"idle");
	statusVal->setStyleSheet(QString("color:%1;background:transparent;").arg(running?GREENH:TXT));
	if (running){ clock.start(); sec->start(); } else sec->stop();
}

void MainWindow::onStartStop()
{
	if (proc && proc->state()!=QProcess::NotRunning){
		proc->terminate(); if(!proc->waitForFinished(1000)) proc->kill();
		return;
	}
	if (ipLine->text().trimmed().isEmpty()){
		log->append("<span style='color:" REDc "'>[!] enter a target first.</span>"); return;
	}
	QString bin=engineLine->text().trimmed(); if(bin.isEmpty()) bin="./nesca4";
	reportPath.clear(); lineBuf.clear();
	QStringList args=buildArgs(reportPath);
	if (proc){ proc->deleteLater(); proc=nullptr; }
	proc=new QProcess(this);
	proc->setWorkingDirectory(QFileInfo(bin).absolutePath());
	connect(proc,&QProcess::readyReadStandardOutput,this,&MainWindow::onReadyStdout);
	connect(proc,&QProcess::readyReadStandardError,this,&MainWindow::onReadyStderr);
	connect(proc,QOverload<int,QProcess::ExitStatus>::of(&QProcess::finished),
		this,[this](int c,QProcess::ExitStatus){ onFinished(c); });
	log->clear(); resetStats();
	log->append(QString("<span style='color:" DIM "'>[*] %1 %2</span>")
		.arg(bin).arg(args.join(' ').toHtmlEscaped()));
	setRunning(true);
	proc->start(bin,args);
	if (!proc->waitForStarted(3000)){
		log->append("<span style='color:" REDc "'>[!] failed to start engine.</span>");
		setRunning(false);
	}
}

QString MainWindow::colorizeLine(const QString &raw)
{
	QString line=raw; while(line.endsWith('\r')) line.chop(1);
	QString esc=line.toHtmlEscaped();
	QString low=line.toLower();
	const char *col=TXT;

	bool hit=low.contains("(passwd)")||low.contains(" pass:")
		||QRegularExpression("\\S+:\\S+@").match(line).hasMatch();
	if (hit){ bruteHits++; cBasic->setText(QString("Basic Auth: %1").arg(bruteHits)); col=GOLD; }
	else if (line.startsWith("Report nesca4 for")){
		foundTargets++; cAlive->setText(QString("Alive: %1").arg(foundTargets));
		auto m=QRegularExpression("Report nesca4 for (\\S+)").match(line);
		if (m.hasMatch()){ QString ip=m.captured(1); vCurrent->setText(ip);
			esc=QString("Report nesca4 for <a style='color:" LINK ";text-decoration:underline'>%1</a>%2")
				.arg(ip.toHtmlEscaped()).arg(line.mid(m.capturedEnd(1)).toHtmlEscaped()); }
		return QString("<span style='color:" GREENH "'>%1</span>").arg(esc);
	}
	else if (line.startsWith("  ports")) col=PORTSc;
	else if (low.contains("rtsp(")||low.contains("hikvision(")||low.contains("ipc(")||low.contains("rvi(")){
		cCameras->setText(QString("Cameras: %1")
			.arg(cCameras->text().section(' ',-1).toInt()+1)); col=GOLD;
	}
	else if (low.contains("ssh(")){ cSSH->setText(QString("SSH: %1")
			.arg(cSSH->text().section(' ',-1).toInt()+1)); col=GOLD; }
	else if (QRegularExpression("^  (http|ftp|webform|smtp|db)\\(").match(line).hasMatch()) col=GOLD;
	else if (low.contains("err")||low.contains("fail")||low.contains("unavailable")
		||low.contains("could not")||low.contains("unable")){ col=REDc; offlineCount++; }
	else if (low.contains("running nesca4")||low.contains("up ips")||low.contains("success")) col=GREENH;

	auto pm=QRegularExpression("(\\d+(?:\\.\\d+)?)% ?targets").match(line);
	if (pm.hasMatch()) progressPct=pm.captured(1).toDouble();

	return QString("<span style='color:%1'>%2</span>").arg(col).arg(esc);
}

void MainWindow::ingest(const QString &chunk)
{
	int sz=chunk.toUtf8().size(); bytesTotal+=sz; graph->pushBytes(sz);
	lineBuf+=chunk; int nl; QString html;
	while ((nl=lineBuf.indexOf('\n'))>=0){
		QString line=lineBuf.left(nl); lineBuf.remove(0,nl+1);
		if (line.trimmed().isEmpty()) continue;
		html+=colorizeLine(line)+"<br>";
	}
	if (!html.isEmpty()){
		log->moveCursor(QTextCursor::End);
		log->insertHtml(html);
		log->verticalScrollBar()->setValue(log->verticalScrollBar()->maximum());
	}
	vTargets->setText(QString("%1 [%2%]").arg(foundTargets).arg(progressPct,0,'f',1));
	vOffline->setText(QString::number(offlineCount));
	vSaved->setText(QString("%1/%2").arg(bruteHits).arg(foundTargets));
	activityVal->setText(bytesTotal>1024?QString("%1kb").arg(bytesTotal/1024)
					   :QString("%1b").arg(bytesTotal));
}

void MainWindow::onReadyStdout(){ if(proc) ingest(QString::fromLocal8Bit(proc->readAllStandardOutput())); }
void MainWindow::onReadyStderr(){ if(proc) ingest(QString::fromLocal8Bit(proc->readAllStandardError())); }

void MainWindow::onSecTick()
{
	int s=clock.elapsed()/1000;
	vIps->setText(QString("%1/s").arg(s>0?(double)foundTargets/s:0,0,'f',1));
	vThreads->setText(threadsLine->text()+"/"+threadsLine->text());
}

void MainWindow::onFinished(int code)
{
	if (!lineBuf.isEmpty()){ log->append(colorizeLine(lineBuf)); lineBuf.clear(); }
	log->append(QString("<span style='color:" DIM "'>[*] finished (exit %1) — "
		"%2 alive, %3 brute hits</span>").arg(code).arg(foundTargets).arg(bruteHits));
	setRunning(false);
	statusVal->setText("Done"); statusVal->setStyleSheet("color:" TXT ";background:transparent;");
}

void MainWindow::onClearLog(){ log->clear(); }
