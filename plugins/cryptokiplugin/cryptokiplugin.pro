TEMPLATE = lib
CONFIG += plugin
CONFIG += c++11
TARGET = sailfishcryptoki
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishcrypto.pri)

HEADERS += $$PWD/cryptokiplugin.h
SOURCES += $$PWD/cryptokiplugin.cpp $$PWD/libloader.cpp

target.path=/usr/lib/Sailfish/Crypto/
INSTALLS += target
