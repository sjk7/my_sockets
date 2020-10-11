TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

INCLUDEPATH += ../../my/include
SOURCES += \
        #../../socktdd.cpp
        ../../msg_server.cpp

HEADERS += \
    ../../include/my/my_linux_sockets_includes.hpp \
    ../../include/my/my_socket_errors.h \
    ../../include/my/my_sockets.hpp \
    ../../include/my/my_sockets_threaded.hpp \
    ../../include/my/my_sockets_utils.h

unix: LIBS += -lpthread
