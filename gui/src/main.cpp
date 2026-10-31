#include <cipherkeeper/core.hpp>

#include <QApplication>
#include <QLabel>
#include <QString>

#include <cstdlib>

int main(int argc, char* argv[]) {
    const QApplication app(argc, argv);

    if (!ck::initialize()) {
        return EXIT_FAILURE;
    }

    const std::string_view version = ck::version();
    QLabel label(QStringLiteral("CipherKeeper %1\nThe vault UI arrives in Phase 2.")
                     .arg(QString::fromUtf8(version.data(), static_cast<qsizetype>(version.size()))));
    label.setWindowTitle(QStringLiteral("CipherKeeper"));
    label.setAlignment(Qt::AlignCenter);
    label.resize(420, 180);
    label.show();

    return QApplication::exec();
}
