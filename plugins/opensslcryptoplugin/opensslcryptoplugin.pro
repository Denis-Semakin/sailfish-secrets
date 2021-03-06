TEMPLATE = lib
CONFIG += plugin hide_symbols link_pkgconfig
TARGET = sailfishcrypto-openssl
TARGET = $$qtLibraryTarget($$TARGET)
DEFINES += SAILFISHCRYPTO_BUILD_OPENSSLCRYPTOPLUGIN
PKGCONFIG += libcrypto

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishcryptopluginapi.pri)

INCLUDEPATH += $$PWD/evp/
DEPENDPATH += $$PWD/evp/
HEADERS += $$PWD/evp/evp_p.h $$PWD/evp/evp_helpers_p.h $$PWD/opensslcryptoplugin.h
SOURCES += $$PWD/evp/evp.cpp $$PWD/opensslcryptoplugin.cpp

target.path=/usr/lib/Sailfish/Crypto/
INSTALLS += target
