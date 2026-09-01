/* nesca4-gui — main window implementation. */
#include "mainwindow.h"

#include <QWidget>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QTextBrowser>
#include <QPushButton>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QLabel>
#include <QProcess>
#include <QTabWidget>
#include <QGroupBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QDir>
#include <QDateTime>
#include <QScrollBar>
#include <QStatusBar>
#include <QTextCursor>

static const char *kStyle =
	"QMainWindow, QWidget { background: #141414; color: #a1a1a1;"
	"  font-family: monospace; font-size: 13px; }"
	"QGroupBox { border: 1px solid #5d5d5d; margin-top: 8px; }"
	"QGroupBox::title { subcontrol-origin: margin; left: 8px; color: #a1a1a1; }"
	"QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextBrowser {"
	"  background: #0b0b0b; color: #b0b0b0; border: 1px solid #3a3a3a;"
	"  selection-background-color: #2e6f52; padding: 2px; }"
	"QPushButton { background: #202020; color: #c0c0c0;"
	"  border: 1px solid #5d5d5d; padding: 5px 14px; }"
	"QPushButton:hover { background: #2a2a2a; }"
	"QPushButton:disabled { color: #555; border-color: #333; }"
	"QCheckBox { color: #a1a1a1; }"
	"QTabBar::tab { background: #1a1a1a; color: #909090; padding: 6px 12px; }"
	"QTabBar::tab:selected { background: #202020; color: MediumSeaGreen; }";

MainWindow::MainWindow(QWidget *parent)
	: QMainWindow(parent), proc(nullptr)
{
	setWindowTitle("nesca4 — network scanner");
	resize(1000, 680);
	setStyleSheet(kStyle);

	/* ---- target / binary group ---- */
	QGroupBox *tgtBox = new QGroupBox("Target");
	QFormLayout *tgtForm = new QFormLayout(tgtBox);

	binEdit = new QLineEdit("./nesca4");
	QPushButton *browseBtn = new QPushButton("...");
	browseBtn->setFixedWidth(34);
	QHBoxLayout *binRow = new QHBoxLayout;
	binRow->addWidget(binEdit);
	binRow->addWidget(browseBtn);
	tgtForm->addRow("nesca4 binary:", binRow);

	targetEdit = new QLineEdit;
	targetEdit->setPlaceholderText("host / CIDR, e.g. 192.168.0.0/24 or example.com");
	tgtForm->addRow("Target(s):", targetEdit);

	portsEdit = new QLineEdit;
	portsEdit->setPlaceholderText("-p, e.g. 80,443 or S:1-1000");
	tgtForm->addRow("Ports:", portsEdit);

	servicesEdit = new QLineEdit;
	servicesEdit->setPlaceholderText("-s, e.g. http:80,rtsp:554,ssh:22,rvi:37777,ipc:80,wf:8080,smtp:25,hik:8000");
	servicesEdit->setToolTip("Services: http ftp rtsp ssh rvi ipc wf smtp hik (name:port)");
	tgtForm->addRow("Services:", servicesEdit);

	/* ---- options group ---- */
	QGroupBox *optBox = new QGroupBox("Options");
	QGridLayout *optGrid = new QGridLayout(optBox);

	scanMethod = new QComboBox;
	scanMethod->addItems({"(default)", "-syn", "-ack", "-window",
		"-maimon", "-xmas", "-fin", "-null", "-udp"});
	threadsSpin = new QSpinBox;
	threadsSpin->setRange(1, 4096);
	threadsSpin->setValue(5);
	noPingChk   = new QCheckBox("-n-ping (skip ping)");
	noScanChk   = new QCheckBox("-n-scan (skip port scan)");
	verboseChk  = new QCheckBox("-v (verbose)");
	verboseChk->setChecked(true);
	onlyOpenChk = new QCheckBox("-onlyopen");

	optGrid->addWidget(new QLabel("Scan method:"), 0, 0);
	optGrid->addWidget(scanMethod, 0, 1);
	optGrid->addWidget(new QLabel("Brute threads:"), 0, 2);
	optGrid->addWidget(threadsSpin, 0, 3);
	optGrid->addWidget(noPingChk, 1, 0);
	optGrid->addWidget(noScanChk, 1, 1);
	optGrid->addWidget(verboseChk, 1, 2);
	optGrid->addWidget(onlyOpenChk, 1, 3);

	/* ---- controls ---- */
	startBtn = new QPushButton("Start scan");
	stopBtn  = new QPushButton("Stop");
	stopBtn->setEnabled(false);
	QHBoxLayout *ctrlRow = new QHBoxLayout;
	ctrlRow->addWidget(startBtn);
	ctrlRow->addWidget(stopBtn);
	ctrlRow->addStretch();

	/* ---- output tabs ---- */
	console = new QPlainTextEdit;
	console->setReadOnly(true);
	console->setMaximumBlockCount(20000);
	report = new QTextBrowser;
	report->setOpenExternalLinks(false);

	QTabWidget *tabs = new QTabWidget;
	tabs->addTab(console, "Console");
	tabs->addTab(report, "Report");

	statusLabel = new QLabel("idle");

	/* ---- assemble ---- */
	QWidget *central = new QWidget;
	QVBoxLayout *root = new QVBoxLayout(central);
	root->addWidget(tgtBox);
	root->addWidget(optBox);
	root->addLayout(ctrlRow);
	root->addWidget(tabs, 1);
	setCentralWidget(central);
	statusBar()->addWidget(statusLabel);

	connect(browseBtn, &QPushButton::clicked, this, &MainWindow::onBrowseBin);
	connect(startBtn, &QPushButton::clicked, this, &MainWindow::onStart);
	connect(stopBtn, &QPushButton::clicked, this, &MainWindow::onStop);
}

MainWindow::~MainWindow()
{
	if (proc && proc->state() != QProcess::NotRunning) {
		proc->kill();
		proc->waitForFinished(1000);
	}
}

void MainWindow::onBrowseBin()
{
	QString f = QFileDialog::getOpenFileName(this, "Select nesca4 binary");
	if (!f.isEmpty())
		binEdit->setText(f);
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
	if (scanMethod->currentIndex() != 0)
		a << scanMethod->currentText();
	a << "-threads-brute" << QString::number(threadsSpin->value());
	if (noPingChk->isChecked())   a << "-n-ping";
	if (noScanChk->isChecked())   a << "-n-scan";
	if (verboseChk->isChecked())  a << "-v";
	if (onlyOpenChk->isChecked()) a << "-onlyopen";

	outReport = QDir::temp().filePath("nesca4-report-"
		+ QString::number(QDateTime::currentMSecsSinceEpoch()) + ".html");
	a << "-html" << outReport;
	return a;
}

void MainWindow::setRunning(bool running)
{
	startBtn->setEnabled(!running);
	stopBtn->setEnabled(running);
	targetEdit->setEnabled(!running);
	statusLabel->setText(running ? "scanning..." : "idle");
}

void MainWindow::appendLog(const QString &text)
{
	console->moveCursor(QTextCursor::End);
	console->insertPlainText(text);
	console->verticalScrollBar()->setValue(
		console->verticalScrollBar()->maximum());
}

void MainWindow::onStart()
{
	if (targetEdit->text().trimmed().isEmpty()) {
		appendLog("[gui] please enter a target.\n");
		return;
	}
	QString bin = binEdit->text().trimmed();
	if (bin.isEmpty()) bin = "./nesca4";

	reportPath.clear();
	QStringList args = buildArgs(reportPath);

	if (proc) { proc->deleteLater(); proc = nullptr; }
	proc = new QProcess(this);
	proc->setWorkingDirectory(QFileInfo(bin).absolutePath());
	connect(proc, &QProcess::readyReadStandardOutput,
		this, &MainWindow::onReadyReadStdout);
	connect(proc, &QProcess::readyReadStandardError,
		this, &MainWindow::onReadyReadStderr);
	connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
		this, [this](int code, QProcess::ExitStatus){ onFinished(code); });

	console->clear();
	appendLog("[gui] " + bin + " " + args.join(' ') + "\n\n");
	setRunning(true);
	proc->start(bin, args);
	if (!proc->waitForStarted(3000)) {
		appendLog("[gui] failed to start: " + proc->errorString() + "\n");
		setRunning(false);
	}
}

void MainWindow::onStop()
{
	if (proc && proc->state() != QProcess::NotRunning) {
		proc->terminate();
		if (!proc->waitForFinished(1500))
			proc->kill();
		appendLog("\n[gui] stopped.\n");
	}
}

void MainWindow::onReadyReadStdout()
{
	if (proc)
		appendLog(QString::fromLocal8Bit(proc->readAllStandardOutput()));
}

void MainWindow::onReadyReadStderr()
{
	if (proc)
		appendLog(QString::fromLocal8Bit(proc->readAllStandardError()));
}

void MainWindow::onFinished(int exitCode)
{
	appendLog("\n[gui] finished (exit " + QString::number(exitCode) + ")\n");
	setRunning(false);

	if (!reportPath.isEmpty() && QFile::exists(reportPath)) {
		QFile f(reportPath);
		if (f.open(QIODevice::ReadOnly)) {
			report->setHtml(QString::fromUtf8(f.readAll()));
			f.close();
			statusLabel->setText("done — report loaded");
		}
	}
}
