/* nesca4-gui — faithful port of the nesca 3 interface. */
#include <QApplication>
#include <QFontDatabase>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
	QApplication app(argc, argv);
	app.setApplicationName("nesca4-gui");
	QFontDatabase::addApplicationFont(":/fonts/Eurostile.ttf");
	QFontDatabase::addApplicationFont(":/fonts/small_font.ttf");
	MainWindow w;
	w.show();
	return app.exec();
}
