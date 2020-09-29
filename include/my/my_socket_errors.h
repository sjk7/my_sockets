// my_socket_errors.h
#pragma once
#include <cerrno>
#include <cstring>
#include <string>
#include <sstream>
#include <stdexcept>

#ifndef __unix
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#endif

namespace my {

template <typename... ARGS> static inline auto strbuild(ARGS... args) {
    std::stringstream ss;
    (ss << ... << args);
    return std::string(ss.str());
}
namespace sockets {
#ifdef _WIN32
    std::string platform_error_str_(int e) {
        DWORD error = e;
        if (error) {
            LPVOID lpMsgBuf;
            DWORD bufLen = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf,
                0, NULL);

            if (bufLen) {
                LPCSTR lpMsgStr = (LPCSTR)lpMsgBuf;
                std::string result(lpMsgStr, lpMsgStr + bufLen);
                LocalFree(lpMsgBuf);
                return result;
            }
        }
        return std::string();
    }

    int platform_error(bool for_socket_error = true) {
        if (for_socket_error) {
            return WSAGetLastError();
        }
        return (int)GetLastError();
    }
#else
    int platform_error(bool = true) { return errno; }
#endif

    std::string platform_error_string(int e = platform_error()) {
#ifdef _WIN32
        return platform_error_str_(e);
#else
        return strerror(e);
#endif
    }

    static inline std::string error_string(int e = 0) {
        if (e == 0) e = platform_error();
        return strbuild("Error code: ", e, " ", platform_error_string(e));
    }

    class sock_exception : std::exception {
        std::string m_what;
        int m_errcode;

        public:
        template <typename ERRCODE, typename... ARGS>
        sock_exception(ERRCODE errcode, ARGS... args)
            : m_what(std::move(strbuild(std::forward<ARGS>(args)...)))
            , m_errcode(errcode) {

            static_assert(std::is_same_v<ERRCODE, int>,
                "first arg to sock_exception should be the socket error code");

            std::cerr << m_what << std::endl;
        }

        virtual const char* what() const noexcept { return m_what.c_str(); }
        int errcode() const noexcept { return m_errcode; }
    };

    bool error_can_continue(int& e, bool is_connecting = false) {
        e = platform_error();
        if (e == 0) return true;
#ifdef _WIN32
        if (is_connecting) {
            if (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEISCONN)
                return true;
        }

        if (e == WSAEALREADY || e == WSAEWOULDBLOCK) {
            return true;
        }
#else
        if (is_connecting) {
            if (e == EAGAIN || e == EALREADY || e == EISCONN) return true;
        }
        if (e == EAGAIN || e == EINTR || e == EINPROGRESS) {
            return true;
        }
#endif
        return false;
    }
} // namespace sockets
} // namespace my