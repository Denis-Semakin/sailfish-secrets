TEMPLATE = app
TARGET = tst_cryptokirequests
target.path = /opt/tests/Sailfish/Crypto/
include($$PWD/../../../lib/libsailfishcrypto.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)
QT += testlib
SOURCES += tst_cryptokirequests.cpp
INSTALLS += target
