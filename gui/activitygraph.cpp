/* nesca4-gui — activity oscilloscope. */
#include "activitygraph.h"
#include <QPainter>
#include <QTimer>
#include <QtGlobal>
#include <cmath>
#include <cstdlib>

static const int MAXS = 240;

ActivityGraph::ActivityGraph(QWidget *parent)
	: QWidget(parent), level(0.0), phase(0.0), active(false)
{
	setMinimumHeight(120);
	samples.fill(0.0, MAXS);
	timer = new QTimer(this);
	connect(timer, &QTimer::timeout, this, &ActivityGraph::tick);
	timer->start(40);
}

void ActivityGraph::pushBytes(int n)
{
	/* map bytes to a 0..1 spike (log-ish), accumulate into level */
	double v = n > 0 ? std::log10((double)n + 1.0) / 4.0 : 0.0;
	if (v > 1.0) v = 1.0;
	level = qMax(level, v);
}

void ActivityGraph::setActive(bool on) { active = on; }

void ActivityGraph::reset()
{
	samples.fill(0.0, MAXS);
	level = 0.0;
	update();
}

void ActivityGraph::tick()
{
	phase += 0.3;
	/* baseline idle jitter + decaying activity spikes */
	double base = active ? 0.06 : 0.02;
	double noise = ((double)(std::rand() % 100) / 100.0 - 0.5) * base;
	double s = level + noise + (active ? 0.04 * std::sin(phase) : 0.0);
	if (s < 0) s = 0;
	if (s > 1) s = 1;
	samples.append(s);
	while (samples.size() > MAXS)
		samples.removeFirst();
	level *= 0.80;   /* decay */
	update();
}

void ActivityGraph::paintEvent(QPaintEvent *)
{
	QPainter p(this);
	p.fillRect(rect(), QColor(8, 8, 8));

	int w = width(), h = height();
	/* faint grid */
	p.setPen(QColor(30, 40, 30));
	for (int x = 0; x < w; x += 28)
		p.drawLine(x, 0, x, h);
	p.setPen(QColor(24, 32, 24));
	for (int y = 0; y < h; y += 22)
		p.drawLine(0, y, w, y);

	/* waveform */
	int n = samples.size();
	if (n < 2)
		return;
	QColor green(60, 200, 110);
	p.setPen(QPen(green, 1.3));
	double mid = h / 2.0;
	QPointF prev;
	for (int i = 0; i < n; ++i) {
		double x = (double)i / (n - 1) * w;
		double amp = samples[i] * (h * 0.45);
		/* mirror around midline for oscilloscope look */
		double y = mid - amp * std::sin(i * 0.7);
		QPointF cur(x, y);
		if (i)
			p.drawLine(prev, cur);
		prev = cur;
	}
	/* leading dot */
	p.setBrush(QColor(120, 255, 150));
	p.setPen(Qt::NoPen);
	p.drawEllipse(prev, 2.2, 2.2);
}
