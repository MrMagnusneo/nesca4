/* nesca4-gui — nesca-style scrolling oscilloscope activity widget. */
#ifndef ACTIVITYGRAPH_H
#define ACTIVITYGRAPH_H

#include <QWidget>
#include <QVector>

class QTimer;

class ActivityGraph : public QWidget {
	Q_OBJECT
public:
	explicit ActivityGraph(QWidget *parent = nullptr);
	void pushBytes(int n);   /* feed traffic volume; drives the wave */
	void setActive(bool on); /* running -> lively, idle -> flat decay */
	void reset();

protected:
	void paintEvent(QPaintEvent *) override;

private slots:
	void tick();

private:
	QVector<double> samples;   /* rolling buffer, newest at back */
	double          level;     /* current activity level 0..1 */
	double          phase;     /* for idle idle-noise */
	bool            active;
	QTimer         *timer;
};

#endif
