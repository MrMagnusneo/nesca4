/* nesca4-gui — nesca-style main window implementation. */
#include "mainwindow.h"
#include "activitygraph.h"

#include <QWidget>
#include <QLineEdit>
#include <QTextEdit>
#include <QTextBrowser>
#include <QPushButton>
#include <QComboBox>
#include <QSpinBox>
#include <QLabel>
#include <QProgressBar>
#include <QProcess>
#include <QTimer>
#include <QTabWidget>
#include <QGroupBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QSplitter>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QDir>
#include <QDateTime>
#include <QScrollBar>
#include <QRegularExpression>
#include <QStatusBar>
#include <QTextCursor>
#include <QFont>

/* ---- nesca dark palette ---- */
static const char *C_BG     = "#0b0d0b";
static const char *C_GRAY   = "#7f8f7f";
static const char *C_GREEN  = "#5fd07a";
static const char *C_GOLD   = "#d4a017";
static const char *C_HIT    = "#ffd24a";
static const char *C_LINK   = "#3aa0ff";
static const char *C_PORTS  = "#4a90d9";
static const char *C_RED    = "#e0605a";
static const char *C_HEAD   = "#b6c2b6";

static QString nescaStyle()
{
	return QString(
	"QMainWindow, QWidget { background:%1; color:%2;"
	"  font-family:'DejaVu Sans Mono','Consolas',monospace; font-size:12px; }"
	"QGroupBox { border:1px solid #35452f; margin-top:8px; }"
	"QGroupBox::title { subcontrol-origin:margin; left:8px; color:%6; }"
	"QLineEdit,QComboBox,QSpinBox { background:#060806; color:#b6d6b6;"
	"  border:1px solid #2a3a26; padding:3px;"
	"  selection-background-color:#2e6f52; }"
	"QLineEdit:focus { border:1px solid #4fd07a; }"
	"QPushButton { background:#16211500; background-color:#152015;"
	"  color:#c6e0c6; border:1px solid #3a5a34; padding:6px 18px; font-weight:bold; }"
	"QPushButton:hover { background-color:#1c2a1c; }"
	"QTextEdit,QTextBrowser { background:#060806; border:1px solid #2a3a26; }"
	"QTabBar::tab { background:#0e120e; color:#7f8f7f; padding:5px 12px;"
	"  border:1px solid #22301f; }"
	"QTabBar::tab:selected { color:%3; border-bottom:2px solid #4fd07a; }"
	"QProgressBar { background:#060806; border:1px solid #2a3a26; text-align:center;"
	"  color:#9fb79f; }"
	"QProgressBar::chunk { background-color:#2e7f4f; }"
	"QScrollBar:vertical { background:#0b0d0b; width:12px; }"
	"QScrollBar::handle:vertical { background:#2a3a26; min-height:20px; }"
	).arg(C_BG).arg(C_GRAY).arg(C_GREEN).arg("").arg("").arg(C_HEAD);
}

static QLabel *statLabel(const QString &v, const char *color)
{
	QLabel *l = new QLabel(v);
	l->setStyleSheet(QString("color:%1; font-weight:bold;").arg(color));
	return l;
}

MainWindow::MainWindow(QWidget *parent)
	: QMainWindow(parent), proc(nullptr), bytesTotal(0),
	  foundTargets(0), bruteHits(0), progressPct(0.0)
{
	setWindowTitle("NESCA4 :: Revealing the Unseen Horizon");
	resize(1080, 760);
	setStyleSheet(nescaStyle());

	/* ---- title ---- */
	QLabel *title = new QLabel("N E S C A 4  ::  Revealing the Unseen Horizon");
	title->setAlignment(Qt::AlignCenter);
	title->setStyleSheet(QString("color:%1; font-size:15px; font-weight:bold;"
		" letter-spacing:2px; padding:6px;").arg(C_HEAD));

	/* ---- inputs ---- */
	QGroupBox *inBox = new QGroupBox;
	QGridLayout *g = new QGridLayout(inBox);
	binEdit = new QLineEdit("./nesca4");
	QPushButton *browse = new QPushButton("...");
	browse->setFixedWidth(32);
	targetEdit = new QLineEdit; targetEdit->setPlaceholderText("IP RANGE  e.g. 62.16.0.0/24  or  example.com");
	portsEdit = new QLineEdit("80,81,88,8080,8888,21,554,8000,37777");
	servicesEdit = new QLineEdit("http:80,ftp:21,rtsp:554,ssh:22,rvi:37777,hik:8000");
	scanMethod = new QComboBox;
	scanMethod->addItems({"-syn","-ack","-window","-maimon","-xmas","-fin","-null","(default)"});
	threadsSpin = new QSpinBox; threadsSpin->setRange(1,10000); threadsSpin->setValue(200);
	timeoutSpin = new QSpinBox; timeoutSpin->setRange(1,60); timeoutSpin->setValue(3);
	startBtn = new QPushButton("START");

	g->addWidget(new QLabel("engine"), 0,0);
	{ QHBoxLayout *r=new QHBoxLayout; r->addWidget(binEdit); r->addWidget(browse); g->addLayout(r,0,1,1,3); }
	g->addWidget(new QLabel("IP RANGE"), 1,0); g->addWidget(targetEdit,1,1,1,3);
	g->addWidget(new QLabel("PORTS"),    2,0); g->addWidget(portsEdit,2,1,1,3);
	g->addWidget(new QLabel("SERVICES"), 3,0); g->addWidget(servicesEdit,3,1,1,3);
	g->addWidget(new QLabel("THREADS"),  4,0); g->addWidget(threadsSpin,4,1);
	g->addWidget(new QLabel("TIMEOUT"),  4,2); g->addWidget(timeoutSpin,4,3);
	g->addWidget(new QLabel("METHOD"),   5,0); g->addWidget(scanMethod,5,1);
	g->addWidget(startBtn,5,3);

	/* ---- stats column ---- */
	QGroupBox *stBox = new QGroupBox("scan");
	QFormLayout *sf = new QFormLayout(stBox);
	stCurrent = statLabel("--", C_GREEN);
	stThreads = statLabel("0", C_HEAD);
	stTargets = statLabel("0", C_GOLD);
	stIps     = statLabel("0/s", C_HEAD);
	stFound   = statLabel("0 / 0", C_HIT);
	stElapsed = statLabel("00:00", C_HEAD);
	auto cap=[](const char*t){ QLabel*l=new QLabel(t); l->setStyleSheet("color:#6a7a6a;"); return l; };
	sf->addRow(cap("Current IP:"), stCurrent);
	sf->addRow(cap("Threads:"),    stThreads);
	sf->addRow(cap("Targets:"),    stTargets);
	sf->addRow(cap("IP/s:"),       stIps);
	sf->addRow(cap("Found/Brute:"),stFound);
	sf->addRow(cap("Elapsed:"),    stElapsed);

	graph = new ActivityGraph;

	QWidget *leftCol = new QWidget;
	QVBoxLayout *lv = new QVBoxLayout(leftCol);
	lv->setContentsMargins(0,0,0,0);
	lv->addWidget(stBox);
	lv->addWidget(graph, 1);

	/* ---- output tabs ---- */
	log = new QTextEdit; log->setReadOnly(true);
	QFont mono("DejaVu Sans Mono"); mono.setStyleHint(QFont::Monospace); mono.setPointSize(10);
	log->setFont(mono);
	report = new QTextBrowser;
	QTabWidget *tabs = new QTabWidget;
	tabs->addTab(log, "Dataflow");
	tabs->addTab(report, "Report");

	QSplitter *split = new QSplitter(Qt::Horizontal);
	split->addWidget(leftCol);
	split->addWidget(tabs);
	split->setStretchFactor(0,0);
	split->setStretchFactor(1,1);
	split->setSizes({260, 820});

	/* ---- assemble ---- */
	QWidget *central = new QWidget;
	QVBoxLayout *root = new QVBoxLayout(central);
	root->addWidget(title);
	root->addWidget(inBox);
	root->addWidget(split, 1);
	setCentralWidget(central);

	progress = new QProgressBar; progress->setRange(0,100); progress->setValue(0);
	progress->setFixedWidth(220); progress->setTextVisible(true);
	statusLabel = new QLabel("idle");
	activityLabel = new QLabel("Activity: 0b");
	statusBar()->addWidget(statusLabel, 1);
	statusBar()->addWidget(activityLabel);
	statusBar()->addPermanentWidget(progress);

	sec = new QTimer(this); sec->setInterval(1000);
	connect(sec, &QTimer::timeout, this, &MainWindow::onSecTick);
	connect(browse, &QPushButton::clicked, this, &MainWindow::onBrowseBin);
	connect(startBtn, &QPushButton::clicked, this, &MainWindow::onStartStop);

	appendHtml(QString("<span style='color:%1'>[*] nesca4-gui ready. "
		"Enter a target and press START.</span>").arg(C_GRAY));
}

MainWindow::~MainWindow()
{
	if (proc && proc->state() != QProcess::NotRunning) {
		proc->kill(); proc->waitForFinished(800);
	}
}

void MainWindow::onBrowseBin()
{
	QString f = QFileDialog::getOpenFileName(this, "Select nesca4 engine binary");
	if (!f.isEmpty()) binEdit->setText(f);
}

QStringList MainWindow::buildArgs(QString &outReport) const
{
	QStringList a;
	if (!targetEdit->text().trimmed().isEmpty())
		a << targetEdit->text().trimmed().split(' ', Qt::SkipEmptyParts);
	if (!portsEdit->text().trimmed().isEmpty())
		a << "-p" << portsEdit->text().trimmed();
	if (!servicesEdit->text().trimmed().isEmpty())
		a << "-s" << servicesEdit->text().trimmed();
	if (scanMethod->currentText().startsWith("-"))
		a << scanMethod->currentText();
	a << "-threads-brute" << QString::number(threadsSpin->value());
	a << "-wait-scan" << QString("%1s").arg(timeoutSpin->value());
	a << "-v";
	outReport = QDir::temp().filePath("nesca4-report-"
		+ QString::number(QDateTime::currentMSecsSinceEpoch()) + ".html");
	a << "-html" << outReport;
	return a;
}

void MainWindow::resetStats()
{
	bytesTotal = 0; foundTargets = 0; bruteHits = 0; progressPct = 0;
	stCurrent->setText("--"); stThreads->setText(QString::number(threadsSpin->value()));
	stTargets->setText("0"); stIps->setText("0/s"); stFound->setText("0 / 0");
	stElapsed->setText("00:00");
	progress->setValue(0); activityLabel->setText("Activity: 0b");
	graph->reset();
}

void MainWindow::setRunning(bool running)
{
	startBtn->setText(running ? "STOP" : "START");
	startBtn->setStyleSheet(running
		? "background-color:#3a1414; color:#ff8a8a; border:1px solid #6a2a2a; font-weight:bold;"
		: "");
	targetEdit->setEnabled(!running);
	graph->setActive(running);
	statusLabel->setText(running ? "scanning..." : "idle");
	if (running) { clock.start(); sec->start(); } else sec->stop();
}

void MainWindow::onStartStop()
{
	if (proc && proc->state() != QProcess::NotRunning) {
		proc->terminate();
		if (!proc->waitForFinished(1200)) proc->kill();
		appendHtml(QString("<span style='color:%1'>[*] stopped.</span>").arg(C_GRAY));
		return;
	}
	if (targetEdit->text().trimmed().isEmpty()) {
		appendHtml(QString("<span style='color:%1'>[!] enter a target first.</span>").arg(C_RED));
		return;
	}
	QString bin = binEdit->text().trimmed(); if (bin.isEmpty()) bin = "./nesca4";
	reportPath.clear(); lineBuf.clear();
	QStringList args = buildArgs(reportPath);

	if (proc) { proc->deleteLater(); proc = nullptr; }
	proc = new QProcess(this);
	proc->setWorkingDirectory(QFileInfo(bin).absolutePath());
	connect(proc, &QProcess::readyReadStandardOutput, this, &MainWindow::onReadyStdout);
	connect(proc, &QProcess::readyReadStandardError, this, &MainWindow::onReadyStderr);
	connect(proc, QOverload<int,QProcess::ExitStatus>::of(&QProcess::finished),
		this, [this](int c, QProcess::ExitStatus){ onFinished(c); });

	log->clear(); resetStats();
	appendHtml(QString("<span style='color:%1'>[*] %2 %3</span>")
		.arg(C_GRAY).arg(bin).arg(args.join(' ').toHtmlEscaped()));
	setRunning(true);
	proc->start(bin, args);
	if (!proc->waitForStarted(3000)) {
		appendHtml(QString("<span style='color:%1'>[!] failed to start: %2</span>")
			.arg(C_RED).arg(proc->errorString()));
		setRunning(false);
	}
}

void MainWindow::appendHtml(const QString &html)
{
	log->moveCursor(QTextCursor::End);
	log->insertHtml(html + "<br>");
	log->verticalScrollBar()->setValue(log->verticalScrollBar()->maximum());
}

QString MainWindow::colorizeLine(const QString &raw)
{
	QString line = raw; while (line.endsWith('\r')) line.chop(1);
	QString esc = line.toHtmlEscaped();
	const char *col = C_GRAY;

	QString low = line.toLower();
	bool hit = low.contains("(passwd)") || low.contains(" pass:")
		|| QRegularExpression("[^\\s]+:[^\\s]+@").match(line).hasMatch();

	if (hit) {
		bruteHits++; col = C_HIT;
	} else if (line.startsWith("Report nesca4 for")) {
		foundTargets++;
		/* highlight the ip after 'for ' */
		QRegularExpression re("Report nesca4 for (\\S+)");
		auto m = re.match(line);
		if (m.hasMatch()) {
			QString ip = m.captured(1);
			stCurrent->setText(ip);
			esc = QString("Report nesca4 for <span style='color:%1;"
				"text-decoration:underline'>%2</span>%3")
				.arg(C_LINK).arg(ip.toHtmlEscaped())
				.arg(line.mid(m.capturedEnd(1)).toHtmlEscaped());
		}
		col = C_GREEN;
		return QString("<span style='color:%1'>%2</span>").arg(C_GREEN).arg(esc);
	} else if (line.startsWith("  ports")) {
		col = C_PORTS;
	} else if (QRegularExpression("^  (http|ftp|rtsp|ssh|rvi|ipc|webform|smtp|hikvision|db)\\(")
			.match(line).hasMatch()) {
		col = C_GOLD;
	} else if (low.contains("err")||low.contains("fail")||low.contains("unavailable")
			||low.contains("could not")||low.contains("unable")) {
		col = C_RED;
	} else if (low.contains("running nesca4")||low.contains("up ips")
			||low.contains("success")||low.startsWith("[ok]")||low.contains("scanning")) {
		col = C_GREEN;
	}
	/* progress % */
	QRegularExpression pr("(\\d+(?:\\.\\d+)?)% ?targets");
	auto pm = pr.match(line);
	if (pm.hasMatch()) progressPct = pm.captured(1).toDouble();

	return QString("<span style='color:%1'>%2</span>").arg(col).arg(esc);
}

void MainWindow::ingest(const QString &chunk)
{
	bytesTotal += chunk.toUtf8().size();
	graph->pushBytes(chunk.toUtf8().size());

	lineBuf += chunk;
	int nl;
	QString html;
	while ((nl = lineBuf.indexOf('\n')) >= 0) {
		QString line = lineBuf.left(nl);
		lineBuf.remove(0, nl + 1);
		if (line.trimmed().isEmpty()) { html += "<br>"; continue; }
		html += colorizeLine(line) + "<br>";
	}
	if (!html.isEmpty()) {
		log->moveCursor(QTextCursor::End);
		log->insertHtml(html);
		log->verticalScrollBar()->setValue(log->verticalScrollBar()->maximum());
	}
	updateStats();
}

void MainWindow::updateStats()
{
	stTargets->setText(QString::number(foundTargets));
	stFound->setText(QString("%1 / %2").arg(foundTargets).arg(bruteHits));
	activityLabel->setText(QString("Activity: %1")
		.arg(bytesTotal > 1024 ? QString("%1kb").arg(bytesTotal/1024)
					: QString("%1b").arg(bytesTotal)));
	if (progressPct > 0) progress->setValue((int)progressPct);
}

void MainWindow::onReadyStdout(){ if (proc) ingest(QString::fromLocal8Bit(proc->readAllStandardOutput())); }
void MainWindow::onReadyStderr(){ if (proc) ingest(QString::fromLocal8Bit(proc->readAllStandardError())); }

void MainWindow::onSecTick()
{
	qint64 ms = clock.elapsed(); int s = ms/1000;
	stElapsed->setText(QString("%1:%2").arg(s/60,2,10,QChar('0')).arg(s%60,2,10,QChar('0')));
	double rate = s > 0 ? (double)foundTargets / s : 0;
	stIps->setText(QString("%1/s").arg(rate,0,'f',1));
	if (proc) stThreads->setText(QString::number(threadsSpin->value()));
}

void MainWindow::onFinished(int code)
{
	if (!lineBuf.isEmpty()) { appendHtml(colorizeLine(lineBuf)); lineBuf.clear(); }
	appendHtml(QString("<span style='color:%1'>[*] finished (exit %2) — "
		"%3 targets, %4 brute hits</span>")
		.arg(C_GRAY).arg(code).arg(foundTargets).arg(bruteHits));
	setRunning(false);
	progress->setValue(100);
	statusLabel->setText("done");
	if (!reportPath.isEmpty() && QFile::exists(reportPath)) {
		QFile f(reportPath);
		if (f.open(QIODevice::ReadOnly)) {
			report->setHtml(QString::fromUtf8(f.readAll())); f.close();
		}
	}
}
