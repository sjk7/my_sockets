// my_linux_sockets_include.hpp
#pragma once

#include "my_sockets_utils.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> // close()static void (*callback)(const std::string&, void* ctx) = nullptr;
#include <netdb.h> // addrinfo, etc
#include <arpa/inet.h> // inet_pton
#include <fcntl.h> // blocking stuff
