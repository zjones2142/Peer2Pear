#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QCoreApplication::setOrganizationName("Peer2Pear");
    QCoreApplication::setApplicationName("Peer2Pear");

    // Set the app icon — this is what Windows shows in notifications
    a.setWindowIcon(QIcon(":/logo.png"));

    MainWindow w;
    w.show();
    return a.exec();
}
