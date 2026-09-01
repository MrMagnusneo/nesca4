/* nesca4-gui — Qt5 desktop frontend for nesca4. */
#include <QApplication>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
	QApplication app(argc, argv);
	app.setApplicationName("nesca4-gui");
	MainWindow w;
	w.show();
	return app.exec();
}
