#include "mainwindow.h"

#include <QApplication>
#include <QLockFile>
#include <QStandardPaths>
#include <QDir>
#include <QMessageBox>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QCoreApplication::setOrganizationName("Peer2Pear");
    QCoreApplication::setApplicationName("Peer2Pear");

    // H2 fix: single-instance guard — prevents concurrent DB migration
    // corruption and duplicate polling connections.
    const QString lockDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(lockDir);
    QLockFile lockFile(lockDir + "/peer2pear.lock");
    lockFile.setStaleLockTime(5000);  // 5 s — auto-recover from crashed instances
    if (!lockFile.tryLock(500)) {
        QMessageBox::warning(nullptr, "Already Running",
            "Another instance of Peer2Pear is already running.\n"
            "Only one instance can run at a time to protect your data.");
        return 1;
    }

    // Set the app icon — this is what Windows shows in notifications
    a.setWindowIcon(QIcon(":/logo.png"));

    MainWindow w;
    w.show();
    return a.exec();
}
