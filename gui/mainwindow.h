/* nesca4-gui — wraps the original nesca_3 UI, driving the nesca4 CLI. */
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QElapsedTimer>
#include <QPoint>

QT_BEGIN_NAMESPACE
namespace Ui { class nesca_3Class; }
QT_END_NAMESPACE
class QProcess;
class QTimer;

class MainWindow : public QMainWindow {
	Q_OBJECT
public:
	explicit MainWindow(QWidget *parent = nullptr);
	~MainWindow() override;

protected:
	void mousePressEvent(QMouseEvent *) override;
	void mouseMoveEvent(QMouseEvent *) override;

private slots:
	void onStartStop();
	void onReadyStdout();
	void onReadyStderr();
	void onFinished(int code);
	void onSecTick();

private:
	QStringList buildArgs(QString &reportPath) const;
	QString servicesFromPorts(const QString &ports) const;
	void setRunning(bool running);
	void ingest(const QString &chunk);
	QString colorizeLine(const QString &line);
	void resetStats();

	Ui::nesca_3Class *ui;
	QProcess *proc;
	QString   engineBin, reportPath, lineBuf;
	QElapsedTimer clock;
	QTimer   *sec;
	QPoint    dragPos;
	long long bytesTotal;
	int foundTargets, bruteHits, offlineCount;
	int camCount, sshCount;
	double progressPct;
};

#endif
