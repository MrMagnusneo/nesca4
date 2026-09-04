/* nesca4-gui — nesca-style main window. */
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QElapsedTimer>

class QLineEdit;
class QTextEdit;
class QTextBrowser;
class QPushButton;
class QComboBox;
class QSpinBox;
class QLabel;
class QProgressBar;
class QProcess;
class QTimer;
class ActivityGraph;

class MainWindow : public QMainWindow {
	Q_OBJECT
public:
	explicit MainWindow(QWidget *parent = nullptr);
	~MainWindow() override;

private slots:
	void onStartStop();
	void onBrowseBin();
	void onReadyStdout();
	void onReadyStderr();
	void onFinished(int code);
	void onSecTick();

private:
	QStringList buildArgs(QString &reportPath) const;
	void   setRunning(bool running);
	void   ingest(const QString &chunk);     /* colorize + parse */
	void   appendHtml(const QString &html);
	QString colorizeLine(const QString &line);
	void   resetStats();
	void   updateStats();

	/* inputs */
	QLineEdit    *binEdit, *targetEdit, *portsEdit, *servicesEdit;
	QComboBox    *scanMethod;
	QSpinBox     *threadsSpin, *timeoutSpin;
	QPushButton  *startBtn;

	/* stats */
	QLabel       *stCurrent, *stThreads, *stTargets, *stIps,
		     *stFound, *stElapsed;
	ActivityGraph*graph;
	QProgressBar *progress;
	QLabel       *statusLabel, *activityLabel;

	/* output */
	QTextEdit    *log;
	QTextBrowser *report;

	/* runtime */
	QProcess     *proc;
	QString       reportPath, lineBuf;
	QElapsedTimer clock;
	QTimer       *sec;
	long long     bytesTotal;
	int           foundTargets, bruteHits;
	double        progressPct;
};

#endif
