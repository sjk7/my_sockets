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
static constexpr const char* newline = "\r\n";

template <typename... ARGS> static inline std::string strbuild(ARGS... args) {
    std::stringstream ss;

    const char* sep = "";
    (((ss << sep << args), sep = " "), ...);
    std::string out(ss.str());
    return out;
}

namespace sockets {

    enum error_codes {
#ifdef _WIN32
        error_not_sock = WSAENOTSOCK,
        error_timedout = WSAETIMEDOUT
#else

        error_not_sock = ENOTSOCK,
        error_timedout = ETIMEDOUT

#endif
    };
    [[maybe_unused]] static inline void set_last_error(
        int err = 0, bool for_sockets = true) {
        if (for_sockets) {
#ifdef __unix
            errno = err;
#else
            if (for_sockets) {
                WSASetLastError(err);
            } else {
                SetLastError(err);
            }
#endif
        }
    }
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
    static inline int platform_error(bool = true) { return errno; }
#endif

    static inline std::string platform_error_string(int e = platform_error()) {
#ifdef _WIN32
        return platform_error_str_(e);
#else
        return strerror(e);
#endif
    }

    [[maybe_unused]] static inline std::string error_string(int e = 0) {
        if (e == 0) {
            e = platform_error();
        }
        return strbuild("Error code:", e, platform_error_string(e));
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

            // perror(m_what.c_str());
        }

        virtual const char* what() const noexcept { return m_what.c_str(); }
        int errcode() const noexcept { return m_errcode; }
    };

    [[maybe_unused]] static inline bool error_can_continue(
        int& e, bool is_connecting = false) {
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

    template <typename... ARGS> static inline void throw_sock_exception(ARGS... args) {
        sock_exception e{platform_error(), "Error number: ", platform_error(), ":",
            platform_error_string(), std::forward<ARGS>(args)...};
        throw e;
    }

    template <typename... ARGS>
    static inline void throw_sock_exception(int errcode, ARGS... args) {
        sock_exception e{
            errcode, "Error number: ", errcode, my::newline, std::forward<ARGS>(args)...};
        throw e;
    }

#ifndef THROW_SOCK_EXCEPTION
#define THROW_SOCK_EXCEPTION(arg, ...) throw_sock_exception(arg, ##__VA_ARGS__)
#endif
} // namespace sockets
} // namespace my
