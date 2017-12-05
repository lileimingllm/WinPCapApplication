
INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

win32 {
INCLUDEPATH += $$PWD/3rdParty/WpdPack/Include
LIBS += $$PWD/3rdParty/WpdPack/Lib/packet.lib \
        $$PWD/3rdParty/WpdPack/Lib/wpcap.lib
}
unix {

}

DEFINES += HAVE_REMOTE

HEADERS += $$PWD/PCapWrapper.h

SOURCES += $$PWD/PCapWrapper.cpp
