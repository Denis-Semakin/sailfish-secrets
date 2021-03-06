TEMPLATE = lib
CONFIG += plugin hide_symbols
TARGET = sailfishsecrets-testpasswordagentauth
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)

DEFINES += SAILFISHSECRETS_TESTPLUGIN
HEADERS += $$PWD/../../../plugins/passwordagentauthplugin/passwordagentplugin.h
SOURCES += $$PWD/../../../plugins/passwordagentauthplugin/passwordagentplugin.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
