/* nesca4-gui — main window. */
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

class QLineEdit;
class QPlainTextEdit;
class QTextBrowser;
class QPushButton;
class QComboBox;
class QSpinBox;
class QCheckBox;
class QLabel;
class QProcess;

class MainWindow : public QMainWindow {
	Q_OBJECT
public:
	explicit MainWindow(QWidget *parent = nullptr);
	~MainWindow() override;

private slots:
	void onStart();
	void onStop();
	void onBrowseBin();
	void onReadyReadStdout();
	void onReadyReadStderr();
	void onFinished(int exitCode);

private:
	QStringList buildArgs(QString &reportPath) const;
	void setRunning(bool running);
	void appendLog(const QString &text);

	/* inputs */
	QLineEdit      *binEdit;
	QLineEdit      *targetEdit;
	QLineEdit      *portsEdit;
	QLineEdit      *servicesEdit;
	QComboBox      *scanMethod;
	QSpinBox       *threadsSpin;
	QCheckBox      *noPingChk;
	QCheckBox      *noScanChk;
	QCheckBox      *verboseChk;
	QCheckBox      *onlyOpenChk;

	/* controls / output */
	QPushButton    *startBtn;
	QPushButton    *stopBtn;
	QPlainTextEdit *console;
	QTextBrowser   *report;
	QLabel         *statusLabel;

	QProcess       *proc;
	QString         reportPath;
};

#endif
