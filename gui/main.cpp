/* nesca4-gui — original nesca_3.ui wired to the nesca4 engine. */
#include <QApplication>
#include <QFontDatabase>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
	QApplication app(argc, argv);
	app.setApplicationName("nesca4-gui");
	QFontDatabase::addApplicationFont(":/nesca_3/Eurostile.ttf");
	QFontDatabase::addApplicationFont(":/nesca_3/small_font.ttf");
	MainWindow w;
	w.show();
	return app.exec();
}
