#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QCoreApplication::setOrganizationName("Peer2Pear");
    QCoreApplication::setApplicationName("Peer2Pear");

    MainWindow w;
    w.show();
    return a.exec();
}
