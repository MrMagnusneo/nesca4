/* nesca4-gui — original nesca_3 UI wired to the nesca4 CLI engine. */
#include "mainwindow.h"
#include "ui_nesca_3.h"

#include <QProcess>
#include <QTimer>
#include <QFile>
#include <QDir>
#include <QFileInfo>
#include <QDateTime>
#include <QScrollBar>
#include <QRegularExpression>
#include <QTextCursor>
#include <QMouseEvent>
#include <QApplication>

#define GREENH  "#1efd00"
#define GOLD    "#d1a000"
#define LINK    "#3aa0ff"
#define REDc    "#d84a3c"
#define PORTSc  "#5a9bd4"
#define DIMc    "#8a8a8a"

MainWindow::MainWindow(QWidget *parent)
	: QMainWindow(parent), ui(new Ui::nesca_3Class), proc(nullptr),
	  engineBin("./nesca4"), bytesTotal(0), foundTargets(0), bruteHits(0),
	  offlineCount(0), camCount(0), sshCount(0), progressPct(0)
{
	ui->setupUi(this);
	setWindowFlags(Qt::FramelessWindowHint);
	QFont f("Eurostile", 9); qApp->setFont(f);

	/* wire the IP-scan controls that map to the nesca4 engine */
	connect(ui->startScanButton_3, &QPushButton::clicked, this, &MainWindow::onStartStop);
	if (ui->clearLogBut) connect(ui->clearLogBut, &QPushButton::clicked,
		[this]{ ui->dataText->clear(); });
	if (ui->exitButton) connect(ui->exitButton, &QPushButton::clicked,
		qApp, &QApplication::quit);

	sec = new QTimer(this); sec->setInterval(1000);
	connect(sec, &QTimer::timeout, this, &MainWindow::onSecTick);

	ui->dataText->setHtml("<span style='color:" DIMc "'>[*] nesca4-gui ready — "
		"enter IP RANGE and press Start.</span><br>");
}

MainWindow::~MainWindow()
{
	if (proc && proc->state()!=QProcess::NotRunning){ proc->kill(); proc->waitForFinished(600); }
	delete ui;
}

/* frameless drag by the top strip */
void MainWindow::mousePressEvent(QMouseEvent *e)
{
	if (e->button()==Qt::LeftButton && e->pos().y()<40)
		dragPos = e->globalPos() - frameGeometry().topLeft();
}
void MainWindow::mouseMoveEvent(QMouseEvent *e)
{
	if ((e->buttons()&Qt::LeftButton) && !dragPos.isNull() && e->pos().y()<40)
		move(e->globalPos() - dragPos);
}

QString MainWindow::servicesFromPorts(const QString &ports) const
{
	QStringList out;
	const auto toks = ports.split(QRegularExpression("[,\\s]+"), Qt::SkipEmptyParts);
	for (QString t : toks) {
		t = t.section(':', -1);           /* drop S:/T: prefixes */
		bool ok=false; int p=t.toInt(&ok); if(!ok) continue;
		const char *svc =
			(p==21)?"ftp": (p==22)?"ssh": (p==25)?"smtp":
			(p==554)?"rtsp": (p==8000)?"hik": (p==37777)?"rvi": "http";
		out << QString("%1:%2").arg(svc).arg(p);
	}
	return out.join(',');
}

QStringList MainWindow::buildArgs(QString &outReport) const
{
	QStringList a;
	const QString tgt = ui->ipLine->text().trimmed();
	if (!tgt.isEmpty()) a << tgt.split(' ', Qt::SkipEmptyParts);
	const QString ports = ui->ipmPortLine->text().trimmed();
	if (!ports.isEmpty()) {
		a << "-p" << ports;
		a << "-s" << servicesFromPorts(ports);
	}
	if (!ui->threadLine->text().trimmed().isEmpty())
		a << "-threads-brute" << ui->threadLine->text().trimmed();
	if (!ui->iptoLine_value->text().trimmed().isEmpty())
		a << "-wait-scan" << (ui->iptoLine_value->text().trimmed()+"s");
	a << "-v";
	outReport = QDir::temp().filePath("nesca4-report-"
		+ QString::number(QDateTime::currentMSecsSinceEpoch()) + ".html");
	a << "-html" << outReport;
	return a;
}

void MainWindow::resetStats()
{
	bytesTotal=0; foundTargets=bruteHits=offlineCount=camCount=sshCount=0; progressPct=0;
	ui->ipLabel->setText("--");
	ui->labelRunningThreads->setText("0/"+ui->threadLine->text());
	ui->labelPendingTargets->setText("0");
	ui->labelSavedValue->setText("0");
	if (ui->labelAnomaly) ui->labelAnomaly->setText("Cameras: 0");
	if (ui->labelBA)      ui->labelBA->setText("Basic Auth: 0");
	if (ui->labelSSH)     ui->labelSSH->setText("SSH: 0");
	if (ui->labelAlives)  ui->labelAlives->setText("Alive: 0");
}

void MainWindow::setRunning(bool running)
{
	ui->startScanButton_3->setText(running ? "Stop" : "Start");
	ui->ipLine->setEnabled(!running);
	if (running){ clock.start(); sec->start(); } else sec->stop();
}

void MainWindow::onStartStop()
{
	if (proc && proc->state()!=QProcess::NotRunning){
		proc->terminate(); if(!proc->waitForFinished(1000)) proc->kill();
		return;
	}
	if (ui->ipLine->text().trimmed().isEmpty()){
		ui->dataText->append("<span style='color:" REDc "'>[!] enter IP RANGE first.</span>");
		return;
	}
	reportPath.clear(); lineBuf.clear();
	QStringList args = buildArgs(reportPath);
	QString bin = engineBin;
	if (proc){ proc->deleteLater(); proc=nullptr; }
	proc = new QProcess(this);
	proc->setWorkingDirectory(QFileInfo(bin).absolutePath());
	connect(proc,&QProcess::readyReadStandardOutput,this,&MainWindow::onReadyStdout);
	connect(proc,&QProcess::readyReadStandardError,this,&MainWindow::onReadyStderr);
	connect(proc,QOverload<int,QProcess::ExitStatus>::of(&QProcess::finished),
		this,[this](int c,QProcess::ExitStatus){ onFinished(c); });
	ui->dataText->clear(); resetStats();
	ui->dataText->append(QString("<span style='color:" DIMc "'>[*] %1 %2</span>")
		.arg(bin).arg(args.join(' ').toHtmlEscaped()));
	setRunning(true);
	proc->start(bin, args);
	if (!proc->waitForStarted(3000)){
		ui->dataText->append("<span style='color:" REDc "'>[!] failed to start engine "
			"(set path / build nesca4).</span>");
		setRunning(false);
	}
}

QString MainWindow::colorizeLine(const QString &raw)
{
	QString line=raw; while(line.endsWith('\r')) line.chop(1);
	QString esc=line.toHtmlEscaped();
	QString low=line.toLower();
	const char *col=DIMc;

	bool hit=low.contains("(passwd)")||low.contains(" pass:")
		||QRegularExpression("\\S+:\\S+@").match(line).hasMatch();
	if (hit){ bruteHits++; if(ui->labelBA) ui->labelBA->setText(QString("Basic Auth: %1").arg(bruteHits)); col=GOLD; }
	else if (line.startsWith("Report nesca4 for")){
		foundTargets++; if(ui->labelAlives) ui->labelAlives->setText(QString("Alive: %1").arg(foundTargets));
		auto m=QRegularExpression("Report nesca4 for (\\S+)").match(line);
		if (m.hasMatch()){ QString ip=m.captured(1); ui->ipLabel->setText(ip);
			esc=QString("Report nesca4 for <a style='color:" LINK ";text-decoration:underline'>%1</a>%2")
				.arg(ip.toHtmlEscaped()).arg(line.mid(m.capturedEnd(1)).toHtmlEscaped()); }
		return QString("<span style='color:" GREENH "'>%1</span>").arg(esc);
	}
	else if (line.startsWith("  ports")) col=PORTSc;
	else if (low.contains("rtsp(")||low.contains("hikvision(")||low.contains("ipc(")||low.contains("rvi(")){
		camCount++; if(ui->labelAnomaly) ui->labelAnomaly->setText(QString("Cameras: %1").arg(camCount)); col=GOLD;
	}
	else if (low.contains("ssh(")){ sshCount++; if(ui->labelSSH) ui->labelSSH->setText(QString("SSH: %1").arg(sshCount)); col=GOLD; }
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
	bytesTotal += chunk.toUtf8().size();
	lineBuf += chunk; int nl; QString html;
	while ((nl=lineBuf.indexOf('\n'))>=0){
		QString line=lineBuf.left(nl); lineBuf.remove(0,nl+1);
		if (line.trimmed().isEmpty()) continue;
		html += colorizeLine(line)+"<br>";
	}
	if (!html.isEmpty()){
		ui->dataText->moveCursor(QTextCursor::End);
		ui->dataText->insertHtml(html);
		ui->dataText->verticalScrollBar()->setValue(ui->dataText->verticalScrollBar()->maximum());
	}
	ui->labelPendingTargets->setText(QString("%1 [%2%]").arg(foundTargets).arg(progressPct,0,'f',1));
	ui->labelSavedValue->setText(QString::number(bruteHits));
}

void MainWindow::onReadyStdout(){ if(proc) ingest(QString::fromLocal8Bit(proc->readAllStandardOutput())); }
void MainWindow::onReadyStderr(){ if(proc) ingest(QString::fromLocal8Bit(proc->readAllStandardError())); }

void MainWindow::onSecTick()
{
	int s=clock.elapsed()/1000;
	ui->labelRunningThreads->setText((proc?"running":"0")
		+QString("/")+ui->threadLine->text());
	Q_UNUSED(s);
}

void MainWindow::onFinished(int code)
{
	if (!lineBuf.isEmpty()){ ui->dataText->append(colorizeLine(lineBuf)); lineBuf.clear(); }
	ui->dataText->append(QString("<span style='color:" DIMc "'>[*] finished (exit %1) — "
		"%2 alive, %3 brute hits</span>").arg(code).arg(foundTargets).arg(bruteHits));
	setRunning(false);
}
