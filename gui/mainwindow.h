/* nesca4-gui — faithful nesca-3 style main window. */
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QWidget>
#include <QElapsedTimer>
#include <QPoint>

class QLineEdit;
class QTextBrowser;
class QLabel;
class QPushButton;
class QProcess;
class QTimer;
class ActivityGraph;

class MainWindow : public QWidget {
	Q_OBJECT
public:
	explicit MainWindow(QWidget *parent = nullptr);
	~MainWindow() override;

protected:
	/* frameless drag */
	void mousePressEvent(QMouseEvent *) override;
	void mouseMoveEvent(QMouseEvent *) override;

private slots:
	void onStartStop();
	void onReadyStdout();
	void onReadyStderr();
	void onFinished(int code);
	void onSecTick();
	void onClearLog();

private:
	QLabel   *L(const QString &t, int x, int y, int w, int h,
		 const char *color, int pt, bool bold=false, int align=0);
	QLineEdit*E(const QString &t, int x, int y, int w, int h);
	QPushButton *B(const QString &t, int x, int y, int w, int h);

	QStringList buildArgs(QString &reportPath) const;
	void setRunning(bool running);
	void ingest(const QString &chunk);
	QString colorizeLine(const QString &line);
	void resetStats();

	/* title / window */
	QPoint    dragPos;

	/* inputs */
	QLineEdit *ipLine, *portsLine, *threadsLine, *timeoutLine, *servicesLine, *engineLine;
	QPushButton *startBtn;

	/* stats */
	QLabel *vCurrent, *vThreads, *vBrute, *vTargets, *vIps, *vSaved, *vOffline;
	/* category counters */
	QLabel *cCameras, *cBads, *cBasic, *cOther, *cOverloads, *cLowloads, *cSSH, *cAlive;
	/* status */
	QLabel *statusVal, *activityVal;
	ActivityGraph *graph;

	/* log */
	QTextBrowser *log;

	/* runtime */
	QProcess *proc;
	QString reportPath, lineBuf;
	QElapsedTimer clock;
	QTimer *sec;
	long long bytesTotal;
	int foundTargets, bruteHits, offlineCount, savedCount;
	double progressPct;
};

#endif
