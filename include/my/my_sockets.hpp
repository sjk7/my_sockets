// my_sockets.hpp
#pragma once

// my_sockets.hpp
#pragma once
#include <cstdint>
#include <cassert>
#include <atomic>
#include <algorithm>
#include "my_socket_errors.h"
#include "my_sockets_utils.h"
#include <memory> // unique_ptr
#include <string>
#include <cstring>
#include <string_view>
#include <vector>
#include <thread>
#include <iostream>
#include <unordered_map>

#ifdef __unix
#include "my_linux_sockets_includes.hpp"
#include <sys/epoll.h>

#else
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#endif

namespace my::sockets {
#ifdef __linux
using raw_socket_handle = int;
#else
using raw_socket_handle = SOCKET;
#endif

using native_socket_type = raw_socket_handle;
static constexpr int const invalid_fd = (raw_socket_handle)-1;
static constexpr raw_socket_handle invalid_sock_handle = (raw_socket_handle)-1;
static constexpr auto invalid_socket = invalid_fd;
static constexpr int const no_error = 0;
struct port_t {
    unsigned int value = {0};
};
struct backlog_type {
    static inline auto constexpr max_backlog = SOMAXCONN;
    int value = max_backlog;
};

enum class blocking_type { non_blocking, blocking };
[[maybe_unused]] static inline std::ostream& operator<<(
    std::ostream& os, const blocking_type b) {
    if (b == blocking_type::non_blocking)
        os << " [non-blocking] ";
    else
        os << " [blocking] ";
    return os;
}
enum class address_family {
    invalid = -1,
    V4 = AF_INET,
    V6 = AF_INET6,
    UNSPEC = AF_UNSPEC
};
[[maybe_unused]] static inline bool address_family_is_valid(address_family fam) noexcept {
    return fam != address_family::invalid;
}

enum class sock_type {
    invalid = -1,
    TCP = SOCK_STREAM,
    DGRAM [[maybe_unused]] = SOCK_DGRAM
};
[[maybe_unused]] static inline bool sock_type_is_valid(sock_type st) {
    return st != sock_type::invalid;
}

enum class domains { af_inet = AF_INET, af_inet6 [[maybe_unused]] = AF_INET6 };
enum class types { stream = SOCK_STREAM, datagram [[maybe_unused]] = SOCK_DGRAM };
enum class protocols { Default = 0 };
enum class shutdown_options {
#ifdef __unix
    shut_read = SHUT_RD,
    shut_write = SHUT_WR,
    shut_read_write = SHUT_RDWR
#else
    shut_read = SD_RECEIVE,
    shut_write = SD_SEND,
    shut_read_write = SD_BOTH
#endif
};
struct close_flags {
    [[maybe_unused]] static inline constexpr uint8_t none = 0;
    static inline constexpr uint8_t immediate = 1;
    static inline constexpr uint8_t graceful = 2;
    static inline constexpr uint8_t linger_for_timeout = 4;
    uint8_t value = {immediate};
    operator uint8_t() const { return value; }
};
struct timeout_ms {
    static constexpr uint32_t thirty_secs = 30000;
    static constexpr uint32_t default_timeout = thirty_secs;
    uint32_t value = {default_timeout};
    operator uint32_t() const noexcept { return value; }
    timeout_ms() : value(default_timeout){};
    timeout_ms(const uint32_t t) : value(t) {}
};
struct timeout_sec {
    using type = int64_t;
    static constexpr type thirty_secs = 30;
    static constexpr type default_timeout = thirty_secs;
    type value = {default_timeout};
    operator type() const noexcept { return value; }
    timeout_sec() : value(default_timeout){};
};

enum class sock_options {
    so_none = 0,
    so_debug = SO_DEBUG,
    /*/
    Indicates that the rules used in validating addresses supplied
        in a bind(2) call should allow reuse of local addresses.
    /*/
    so_reuseaddr = SO_REUSEADDR,
    /*/
          Gets the socket type as an integer (e.g., SOCK_STREAM).  This
          socket option is read-only.
/*/
    so_type = SO_TYPE,
    so_error = SO_ERROR,
    so_dontroute = SO_DONTROUTE,
    so_broadcast = SO_BROADCAST,
    // Sets or gets the maximum socket send buffer in bytes.
    so_sndbuf = SO_SNDBUF,
    // Sets or gets the maximum socket receive buffer in bytes.
    so_recvbuf = SO_RCVBUF,
#ifdef __unix
    /*/
    Using this socket option, a privileged (CAP_NET_ADMIN) process
        can perform the same task as SO_RCVBUF, but the rmem_max limit
        can be overridden.
    /*/
    so_sndbuffforce = SO_SNDBUFFORCE,
    /*/
    Using this socket option, a privileged (CAP_NET_ADMIN) process
        can perform the same task as SO_SNDBUF, but the rmem_max limit
        can be overridden.
    /*/
    so_recvbufforce = SO_RCVBUFFORCE,
#endif
    /*/
    int flags =1;
    if (setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags))) {
    perror("ERROR: setsocketopt(), SO_KEEPALIVE"); exit(0); }; on the server side, and
    read() will be unblocked when the client is down. See:
    https://holmeshe.me/network-essentials-setsockopt-SO_KEEPALIVE/
    /*/
    so_keepalive = SO_KEEPALIVE,
    /*/
     * If this option is set, out-of-band data received on the socket is placed in the
     normal input queue. This permits it to be read using read or recv without
     specifying the MSG_OOB flag.
     /*/
    so_oobinline = SO_OOBINLINE,
#ifdef __unix
    // disable UDP checksums on packets
    so_no_check = SO_NO_CHECK,
    so_priority = SO_PRIORITY,
#endif
    so_linger = SO_LINGER,
#ifdef __unix
    so_bsdcompar = SO_BSDCOMPAT,
    // Permits multiple AF_INET or AF_INET6 sockets to be bound to an
    // identical socket address.
    so_reuseport = SO_REUSEPORT,
    so_passcred = SO_PASSCRED,
    so_peercred = SO_PEERCRED,
#endif
    so_rcvlowlat = SO_RCVLOWAT,
    so_sndlowlat = SO_SNDLOWAT,
    // Care! In linux, optval is of type struct timeval,
    // but in 'doze it's just a DWORD of millisecs.
    so_rcvtimeeo = SO_RCVTIMEO,
    so_sndtimeeo = SO_SNDTIMEO
};

static inline std::unordered_map<int, std::string> sock_options_map;
static inline void build_sock_options_map() {
    if (sock_options_map.empty()) {
        auto& m = sock_options_map;
        m[(int)sock_options::so_broadcast] = "SO_BROADCAST";
        m[(int)sock_options::so_debug] = "SO_DEBUG";
        m[(int)sock_options::so_dontroute] = "SO_DONTROUTE";
        m[(int)sock_options::so_error] = "SO_ERROR";
        m[(int)sock_options::so_none] = "NONE";
        m[(int)sock_options::so_keepalive] = "SO_KEEPALIVE";
        m[(int)sock_options::so_linger] = "SO_LINGER";
        m[(int)sock_options::so_oobinline] = "SO_OOBINLINE";
        m[(int)sock_options::so_rcvlowlat] = "SO_RCVLOWLAT";
        m[(int)sock_options::so_rcvtimeeo] = "SO_RCVTIMEEO";
        m[(int)sock_options::so_recvbuf] = "SO_RECVBUF";
        m[(int)sock_options::so_reuseaddr] = "SO_REUSEADDR";
        m[(int)sock_options::so_sndbuf] = "SO_SNDBUF";
        m[(int)sock_options::so_sndlowlat] = "SO_SNDLOWLAT";
        m[(int)sock_options::so_sndtimeeo] = "SO_SNDTIMEEO";
        m[(int)sock_options::so_type] = "SO_TYPE";

#ifdef __unix
        m[(int)sock_options::so_priority] = "SO_PRIORITY";
        m[(int)sock_options::so_recvbufforce] = "SO_RECVBUFFFORCE";
        m[(int)sock_options::so_reuseport] = "SO_REUSEPORT";
        m[(int)sock_options::so_sndbuffforce] = "SO_SNDBUFFFORCE";
        m[(int)sock_options::so_passcred] = "SO_PASSCRED";
        m[(int)sock_options::so_peercred] = "SO_PEERCRED";
        m[(int)sock_options::so_bsdcompar] = "SO_BSDCOMPAR";
        m[(int)sock_options::so_no_check] = "SO_NO_CHECK";
#endif
    }
}

[[maybe_unused]] static inline std::ostream& operator<<(
    std::ostream& os, const sock_options& sp) {
    if (sock_options_map.empty()) {
        build_sock_options_map();
    }

    const auto found = sock_options_map.find((int)sp);
    if (found == sock_options_map.cend()) {
        os << "Unknown socket option";
    } else {
        const auto& pr = found;
        std::string_view sv = pr->second;
        os << sv;
    }

    return os;
}

namespace detail {
    namespace raw_socket_helpers {

        template <typename T>
        inline auto set_sock_opt(
            const raw_socket_handle h, const T optval, sock_options optname) {

            assert(h != invalid_fd);
            const auto opt = static_cast<int>(optname);
            auto len = (socklen_t)sizeof(optval);
            //'doze requires optval as char*
            auto ret = setsockopt(h, SOL_SOCKET, opt, (const char*)&optval, len);
            if (ret != no_error) {
                THROW_SOCK_EXCEPTION(
                    "set_sock_opt failed, for handle:", h, ",and optname", optname);
            }
            return ret;
        }

        template <typename T>
        inline auto get_sock_opt(
            const raw_socket_handle sock, T& what, sock_options optname) {

            assert(sock != invalid_fd);
            auto len = (socklen_t)sizeof(what);
            // 'doze only accepts char* here
            auto ret = ::getsockopt(sock, SOL_SOCKET, (int)optname, (char*)&what, &len);
            assert(ret == no_error);
            if (ret != no_error) {
                THROW_SOCK_EXCEPTION("get_sock_opt");
            }
            return ret;
        }
    } // namespace raw_socket_helpers
    struct client_tag {
        inline static constexpr bool is_server = false;
        inline static constexpr bool is_client = true;
        [[maybe_unused]] inline static constexpr bool is_server_client = false;
    };
    struct server_tag {
        inline static constexpr bool is_server = true;
        inline static constexpr bool is_client = false;
        [[maybe_unused]] inline static constexpr bool is_server_client = false;
    };

    struct server_client_tag {
        inline static constexpr bool is_server = false;
        inline static constexpr bool is_client = false;
        [[maybe_unused]] inline static constexpr bool is_server_client = true;
    };

    template <typename TAG> struct endpoint : my::no_copy<endpoint<TAG>> {
        using CLIENTORSERVER = TAG;

        private:
        address_family m_family = address_family::invalid;
        sock_type m_socktype = sock_type::invalid;

        std::string m_host;
        port_t m_port = port_t{};

        struct addrinfo_deleter {
            void operator()(struct addrinfo* ptr) {
                if (ptr) {
                    ::freeaddrinfo(ptr);
                    ptr = nullptr;
                }
            }
        };
        std::unique_ptr<struct addrinfo, addrinfo_deleter> m_addrinfo;

        public:
        [[nodiscard]] port_t port() const { return m_port; }
        [[nodiscard]] std::string_view host() const { return m_host; }
        [[nodiscard]] address_family family() const { return this->m_family; }
        operator struct addrinfo*() const { return m_addrinfo.get(); }

        template <typename INT, typename... ARGS>
        std::string error_string(INT e, ARGS... args) {
#ifdef __unix
            std::string serr(gai_strerror(e));
            std::string more = my::strbuild(args...);
            std::stringstream ss;
            ss << "endpoint error " << e << " : " << serr << ":" << more;
            return std::string(ss.str());
#else
            // They reckon gai_strerror is not thread-safe in 'doze,
            // and you are better off using WSAGetLastError().
            return my::sockets::error_string(e);
#endif
        }

        [[nodiscard]] bool is_valid() const { return m_addrinfo.get() != nullptr; }
        // create an empty endpoint object:
        endpoint() = default;
        endpoint(std::string_view host, port_t port,
            address_family family = address_family::V4)
            : m_host(host), m_port(port) {
            auto ret = build(host, port, family);
            if (ret) {
                THROW_SOCK_EXCEPTION(ret, "Endpoint construction failed");
            }
        }

        private:
        using vec_t = std::vector<std::string>;
        vec_t m_results;
        int build(std::string_view host, port_t port,
            address_family fam = address_family::V4, sock_type s_type = sock_type::TCP) {

            assert(address_family_is_valid(fam));
            this->m_family = fam;
            this->m_socktype = s_type;
            assert(sock_type_is_valid(s_type));
            m_addrinfo.reset(nullptr);
            m_results.clear();

            if constexpr (TAG::is_server) {
                if (host.empty()) host = "0.0.0.0";
            }

            struct addrinfo hints = prepare_hints(host, fam, s_type);
            struct addrinfo* list = {};
            auto strport = std::to_string(port.value);
            auto sport = strport.c_str();
            int ret = ::getaddrinfo(host.data(), sport, &hints, &list);
            if (ret) {
                m_addrinfo.reset();
                std::string info(
                    error_string(ret, ", for host:", m_host, ":", m_port.value));
                THROW_SOCK_EXCEPTION(ret, "[getaddrinfo failed]", my::newline, info);
            }
            m_addrinfo.reset(list);
            enumerate();

            return ret;
        }
        void enumerate() noexcept {
#ifndef ADDRINFOA
#define ADDRINFOA addrinfo
#endif

            m_results.clear();
            ADDRINFOA* p = m_addrinfo.get();

            char buf[INET6_ADDRSTRLEN] = {0};
            while (p) {
                memset(&buf[0], 0, INET6_ADDRSTRLEN);
                char* pw = get_ip_str(p->ai_addr, &buf[0], INET6_ADDRSTRLEN);
                if (pw) {
                    m_results.push_back(pw);
                }
                p = p->ai_next;
            }
        }

        static char* get_ip_str(const struct sockaddr* sa, char* s, size_t maxlen) {
            switch (sa->sa_family) {
                case AF_INET:
                    inet_ntop(AF_INET, &(((struct sockaddr_in*)sa)->sin_addr), s, maxlen);
                    break;

                case AF_INET6:
                    inet_ntop(
                        AF_INET6, &(((struct sockaddr_in6*)sa)->sin6_addr), s, maxlen);
                    break;

                default: strncpy(s, "Unknown AF", maxlen); return nullptr;
            }

            return s;
        }

        struct addrinfo prepare_hints(std::string_view saddr = "",
            address_family af = address_family::V4, const sock_type st = sock_type::TCP,
            int flags = 0) {
            struct addrinfo hints {};
            struct in6_addr serveraddr {};

            memset(&hints, 0, sizeof(struct addrinfo));

            if (af == address_family::UNSPEC) {
                if (saddr.find("::") == std::string::npos) {
                    for (const auto d : saddr) {
                        if (d == '.') {
                        } else {
                            if (!isdigit(d)) {
                                af = address_family::V4;
                            }
                        }
                    }
                } else {
                    // likely ipv6 is valid here
                }
                int rc = inet_pton(AF_INET, saddr.data(), &serveraddr);
                if (rc == 1) /* valid IPv4 text address? */
                {
                    hints.ai_family = AF_INET;
                    hints.ai_flags |= AI_NUMERICHOST;
                } else {
                    rc = inet_pton(AF_INET6, saddr.data(), &serveraddr);
                    if (rc == 1) /* valid IPv6 text address? */
                    {
                        hints.ai_family = AF_INET6;
                        hints.ai_flags |= AI_NUMERICHOST;

                    } else {
                        THROW_SOCK_EXCEPTION(-2, "Address ", saddr,
                            " is neither a valid ipv6 or ipv4 address", my::newline);
                    }
                }

            } else {
                if constexpr (CLIENTORSERVER::is_server) {
                    if (saddr.empty() || saddr == "0.0.0.0") {
                        flags |= AI_PASSIVE; // choose the ip for me
                    }
                }
                hints.ai_family = static_cast<int>(af); /* Allow IPv4 or IPv6 */
                hints.ai_socktype = static_cast<int>(st); /* Datagram socket */
                hints.ai_flags = flags;
                hints.ai_protocol = 0; /* Any protocol */
            }
            return hints;
        }
    };
    template <typename socket> inline static int destroy_socket(socket&) noexcept;

    static inline int make_blocking(const int socket, bool is_blocking) {
        int ret = 0;

#ifndef __unix
        /// @note windows sockets are created in blocking mode by default
        // currently on windows, there is no easy way to obtain the socket's current
        // blocking mode since WSAIsBlocking was deprecated
        u_long non_blocking = is_blocking ? 0 : 1;
        ret = ioctlsocket(socket, FIONBIO, &non_blocking);
#else
        const int flags = fcntl(socket, F_GETFL, 0);
        if ((flags & O_NONBLOCK) && !is_blocking) {
            // info("set_blocking_mode(): socket was already in non-blocking mode");
            return ret;
        }
        if (!(flags & O_NONBLOCK) && is_blocking) {
            // info("set_blocking_mode(): socket was already in blocking mode");
            return ret;
        }
        if (is_blocking) {
            // std::cout << "is blocking!!" << std::endl;
        }
        ret = fcntl(
            socket, F_SETFL, is_blocking ? flags ^ O_NONBLOCK : flags | O_NONBLOCK);
#endif

        return ret;
    }

    struct peer_info {
        std::string ip;
        port_t port{0};
    };

    [[maybe_unused]] static inline peer_info get_peer_info(sockaddr& addr) {

        peer_info pi;
        char ipstr[INET6_ADDRSTRLEN] = {0};

        // deal with both IPv4 and IPv6:
        if (addr.sa_family == AF_INET) {
            auto addrv4 = reinterpret_cast<sockaddr_in*>(&addr);
            struct sockaddr_in* s = addrv4;
            port_t prt{ntohs(s->sin_port)};
            pi.port = prt;
            inet_ntop(AF_INET, &s->sin_addr, &ipstr[0], sizeof ipstr);
        } else { // AF_INET6
            auto addrv6 = reinterpret_cast<sockaddr_in6*>(&addr);
            struct sockaddr_in6* s = addrv6;
            port_t port{ntohs(s->sin6_port)};
            pi.port = port;
            inet_ntop(AF_INET6, &s->sin6_addr, &ipstr[0], sizeof ipstr);
        }

        pi.ip = ipstr;
        return pi;
    }

    template <typename OS = std::ostream, typename SERVER_CLIENT>
    inline OS& operator<<(OS& os, const SERVER_CLIENT& sc) {
        auto& pi = sc.peer_info();
        os << pi.ip;
        os << ":" << pi.port.value;
        os << " [uid:" << sc.uid() << "]";
        return os;
    }

    // NOTE: NOT implicitly convertible to socket handle
    // for type safety reasons, use .handle().
    struct socket_t : my::no_copy<socket_t> {

        using fd_type = raw_socket_handle;
        explicit socket_t() : m_fd(invalid_sock_handle) {}

        explicit socket_t(fd_type sck, blocking_type bt = blocking_type::non_blocking)
            : m_fd(sck), m_blocking(bt) {

            if (m_fd != invalid_sock_handle) make_blocking(m_blocking);
            assert(m_fd != 1);
        }
        // Destructor brutally closes socket.
        // If you need different behaviour, do what you want in
        // your derived class, and clear the handle.
        virtual ~socket_t() {
            if (is_valid()) {
                ::my::sockets::detail::destroy_socket(*this);
            }
            m_fd = invalid_fd;
        }

        socket_t(socket_t&& rhs) noexcept { swap(rhs, *this); }

        socket_t& operator=(socket_t&& rhs) noexcept {
            std::swap(m_fd, rhs.m_fd);
            std::swap(m_blocking, rhs.m_blocking);
            return *this;
        }

        int make_blocking(blocking_type want_blocking = blocking_type::non_blocking) {
            const int ret = my::sockets::detail::make_blocking(
                m_fd, want_blocking == blocking_type::blocking);
            if (ret == 0) {
                m_blocking = want_blocking;
            } else {
                THROW_SOCK_EXCEPTION(
                    "make_blocking(", want_blocking, ") failed.", my::newline);
            }
            assert(m_fd != 1);
            return ret;
        }
        bool is_blocking() const noexcept {
            return (m_blocking == blocking_type::blocking);
        }
        blocking_type blocking_mode() const noexcept { return m_blocking; }
        inline friend bool operator==(const socket_t& rhs, const socket_t& lhs) {
            return rhs.m_fd == lhs.m_fd;
        }
        inline friend bool operator!=(const socket_t& rhs, const socket_t& lhs) {
            return rhs.m_fd != lhs.m_fd;
        }

        private:
        fd_type m_fd = invalid_fd;
        blocking_type m_blocking = blocking_type::non_blocking;

        inline friend void swap(socket_t& lhs, socket_t& rhs) {
            using std::swap;
            swap(lhs.m_fd, rhs.m_fd);
            swap(lhs.m_blocking, rhs.m_blocking);
        }

        public:
        fd_type handle() const { return m_fd; }
        bool is_valid() const { return m_fd != invalid_fd && m_fd >= 0; }
        void invalidate() { m_fd = invalid_fd; }

        protected:
        void assign_handle(fd_type fd, blocking_type bt) {
            // assert(m_fd == invalid_fd);
            m_fd = fd;
            if (fd != invalid_sock_handle) {
                make_blocking(bt);
            }
        }
    };

    template <typename SRV> static inline void apply_reuse_address(const SRV& server) {
#ifndef SO_REUSEPORT
#define SO_REUSEPORT 0
#endif
        const auto reuse_address = server.reuse_address();
        int opt = 0;
        if (reuse_address) {
            opt = 1;
        }
        sock_options props{sock_options::so_reuseaddr};

        if (reuse_address) {
            raw_socket_helpers::set_sock_opt(server.handle(), &opt, props);
        }
    }

    template <typename SRV> static inline int bind(const SRV& server) {

        apply_reuse_address(server);

        const addrinfo* ai = server.get_addrinfo();

        auto sz = sizeof(sockaddr);
        auto fam = server.family();
        if (fam == address_family::V6) {
            auto serv_addr = (sockaddr_in6*)(ai);
            serv_addr->sin6_flowinfo = 0;
            serv_addr->sin6_family = AF_INET6;
            serv_addr->sin6_addr = in6addr_any;
            serv_addr->sin6_port = htons(server.port().value);
            sz = sizeof(sockaddr_in6);
        }
        const int ret = ::bind(server.handle(), ai->ai_addr, static_cast<socklen_t>(sz));
        if (ret != no_error) {
            THROW_SOCK_EXCEPTION("Bind, for host failed: ", server.host(), ":",
                server.port().value, my::newline);
        }
        return ret;
    }

    template <typename SERVER>
    static inline int listen(const SERVER& srv, backlog_type blog = backlog_type{}) {

        int ret = ::listen(srv.handle(), blog.value);
        if (ret != no_error) {
            THROW_SOCK_EXCEPTION(
                "listen failed for host: ", srv.host(), ":", srv.port().value);
        }

        return ret;
    }

    template <typename socket> static int destroy_socket(socket& sock) noexcept {

        assert(sock.is_valid());
        if (!sock.is_valid()) {
            return EINVAL;
        }
#ifdef _WIN32
        auto ret = ::closesocket(sock.handle());
#else
        auto ret = close(sock.handle());
#endif
        sock.invalidate();
        return ret;
    }

    inline static int shutdown_socket(const socket_t& sock,
        shutdown_options opts = shutdown_options::shut_read_write) noexcept {
        return ::shutdown(sock.handle(), (int)opts);
    }

    namespace raw_socket_helpers {
        // why clang mistakes this as not being used, I have no idea!
        [[maybe_unused]] static inline native_socket_type create_native_socket(

            domains domain = domains::af_inet, types type = types::stream,
            protocols protocol = protocols::Default) {

            auto sck = ::socket((int)domain, (int)type, (int)protocol);
            if (sck == invalid_fd) {
                THROW_SOCK_EXCEPTION("Create_native socket failed: ");
            }

            return sck;
        }

        [[maybe_unused]] static inline socket_t create_socket(
            blocking_type bt = blocking_type::non_blocking,
            domains domain = domains::af_inet, types type = types::stream,
            protocols protocol = protocols::Default) {

            auto sck = ::socket((int)domain, (int)type, (int)protocol);
            if (sck == invalid_fd) {
                THROW_SOCK_EXCEPTION("Create_socket failed: ", platform_error_string());
            }
            socket_t retval;
            try {
                socket_t socket{sck, bt};
                retval = std::move(socket);
            } catch (const sock_exception& e) {
                THROW_SOCK_EXCEPTION("Create_socket failed: ", e.what());
            }

            return retval;
        }
    } // namespace raw_socket_helpers
    /*/
Setting l_onoff to FALSE causes member l_linger to be ignored and the
default close(2) behavior implied. That is, the close(2) call will return immediately
to the caller, and any pending data will be delivered if possible.

Setting l_onoff to TRUE causes the value of member l_linger to be significant.
When l_linger is nonzero, this represents the time in seconds for the timeout period
to be applied at close(2) time (the close(2) call will "linger"). If the pending data
and successful close occur before the timeout occurs, a successful return takes place.
Otherwise, an error return occur and errno is set to the value of EWOULDBLOCK.

Setting l_onoff to TRUE and setting l_linger to zero causes the connection to be
aborted and any pending data is immediately discarded upon close(2).
/*/
    inline static auto set_sock_linger(
        socket_t& sock, bool linger, timeout_sec linger_secs = timeout_sec{}) {
        struct linger l = {};
        if (linger)
            l.l_onoff = 1;
        else
            l.l_onoff = 0;

        l.l_linger = (uint32_t)linger_secs.value;
        return raw_socket_helpers::set_sock_opt(sock.handle(), l,
            my::sockets::sock_options{my::sockets::sock_options::so_linger});
    }

    inline static auto set_sock_no_linger(socket_t& sock) {
        struct linger l = {};
        l.l_onoff = 1;
        l.l_linger = 0;
        return raw_socket_helpers::set_sock_opt(
            sock.handle(), l, sock_options{my::sockets::sock_options::so_linger});
    }

    /*/
        Setting l_onoff to FALSE causes member l_linger to be ignored and the
    default close(2) behavior implied. That is, the close(2) call will return
    immediately to the caller, and any pending data will be delivered if possible.
    /*/
    inline static auto set_sock_default_linger(socket_t& sock) {
        struct linger l = {};
        l.l_onoff = 0;
        l.l_linger = 0;
        return raw_socket_helpers::set_sock_opt(
            sock.handle(), l, sock_options{sock_options::so_linger});
    }
    // always closes socket, and does not throw so you can safely
    // use this in destructors.
    [[maybe_unused]] inline static int close_socket(socket_t& sock,
        close_flags flags = close_flags{},
        shutdown_options opts = shutdown_options::shut_read_write,
        timeout_sec timeout_secs = timeout_sec{}) noexcept {

        assert(sock.is_valid());
        if (!sock.is_valid()) {
            return EINVAL;
        }

        if (flags & sockets::close_flags::immediate) {
            set_sock_no_linger(sock);
            return destroy_socket(sock);
        }
        int ret = sockets::no_error;

        if (flags & sockets::close_flags::graceful) {
            if (flags & sockets::close_flags::linger_for_timeout) {
                ret = set_sock_linger(sock, true, timeout_secs);
            } else {
                // ensure default linger:
                ret = set_sock_default_linger(sock);
            }
            if (ret) return ret;

            shutdown_socket(sock, opts);
            // we go ahead and close the socket,
            // regardless whether shutdown failed or not.
            ret = destroy_socket(sock);
        }
        return ret;
    }

    template <typename ADDRINFO>
    int connect_to_server(my::timing::stopwatch_t& sw, const raw_socket_handle fd,
        const ADDRINFO& addr, bool orig_blocking_state,
        timeout_ms timeout = timeout_ms{}) {

        int blocking_ret = my::sockets::detail::make_blocking(fd, false);
        assert(blocking_ret == no_error);
        if (blocking_ret) {
            perror("Unable to set to unblocking state in connect_to_server");
            return EFAULT;
        }

        assert(addr.is_valid() && "addrinfo not valid");
        if (!addr.is_valid()) {
            perror("Addrinfo not valid in connect_to_server!");
            return -EFAULT;
        }
        const struct addrinfo* paddr = addr;
        int ret = 0;
        int ctr = 0;

        while (sw.elapsed_ms().count() < timeout.value) {
            ++ctr;
            if (addr.family() == address_family::V6) {
                const struct sockaddr_in6* in6 = (sockaddr_in6*)paddr->ai_addr;
                ret = ::connect(fd, (sockaddr*)in6, (socklen_t)sizeof(sockaddr_in6));
            } else {
                const struct sockaddr* sin = (sockaddr*)paddr->ai_addr;
                ret = ::connect(fd, sin, (socklen_t)sizeof(sockaddr));
            }

            if (ret == -1) {
                int e = 0;
#ifdef _WIN32
#define CONN_SUCCESS WSAEISCONN
#else
#define CONN_SUCCESS EISCONN
#endif
                if (error_can_continue(e, true)) {
                    if (e == CONN_SUCCESS) {
                        ret = 0;
                        break;
                    }
                    std::this_thread::sleep_for(1ms);
                    continue;
                } else {

                    break;
                }
            }
        }

        if (ret && sw.elapsed_ms().count() >= timeout.value) {

#ifndef _WIN32
            errno = sockets::error_codes::error_timedout;
            ret = errno;
#else
            WSASetLastError(sockets::error_codes::error_timedout);
            ret = sockets::error_codes::error_timedout;
#endif
        }

        blocking_ret = make_blocking(fd, orig_blocking_state);
        assert(blocking_ret == no_error);
        using namespace std;
        if (ret == 0) {
            //   cout << "Connected to " << addr.host()
            //       << ". Connected in: " << sw.elapsed_ms().count() << " ms, "
            //       << "after looping " << ctr << " times" << endl;
        }
        return ret;
    }

    // returns whatever predicate does. (suggest how many bytes recvd)
    // returns a negative number if there's some kind of network error.
    template <typename PRED>
    static inline int sock_read_until(raw_socket_handle sck, PRED&& pred) {

        static constexpr int BUFLEN = 512;
        char buf[BUFLEN];
        memset(&buf[0], 0, BUFLEN);
        int e = 0;
        std::string_view empty_string_buf{};
        int tot_rec = 0;

        while (true) {
            auto ret = ::recv(sck, &buf[0], BUFLEN, MSG_NOSIGNAL);
            if (ret < 0) {
                if (!error_can_continue(e)) {
                    return -e;
                }
                const int predret = pred(empty_string_buf);
                if (predret) {
                    return predret;
                }

            } else if (ret > 0) {
                tot_rec += ret;
                const auto sz = static_cast<std::string::size_type>(ret);
                const int predret = pred(std::string_view{&buf[0], sz});
                if (predret) return predret;

            } else {
                return 0; // other end closed connection here
            }
        }
        return 0;
    }

    template <typename CB, typename PRED>
    // return 0 on success (meaning we sent all the data).
    // Either we send it all, or we fail.
    static inline int sock_send_string(
        const raw_socket_handle sock, std::string_view s, CB on_send_idle, PRED pred) {
        const char* ptr = s.data();
        const char* end = ptr + s.size();
        int sent = 0;
        my::timing::stopwatch_t sw;

        while (ptr < end) {
            const auto remain = end - ptr;
            const int rem = static_cast<int>(remain);
            auto ret = ::send(sock, ptr, rem, MSG_NOSIGNAL);
            if (ret == 0) {
                return 0; // client closed connection
            }
            if (ret < 0) {
                int e = 0;
                if (error_can_continue(e)) {

                    ret = on_send_idle();
                    if (ret) {
                        return ret;
                    }
                    std::this_thread::yield();
                    continue;
                } else {
                    return -e;
                }
            }

            const int predret = pred(sw.elapsed_ms().count());
            if (predret) {
                return predret;
            }
            sent += ret;
            assert(ret > 0);
            ptr += ret;
        }
        return no_error;
    }

#ifdef _WIN32
    struct winsock_manager {
        static inline uint32_t counter = 0;
        winsock_manager() {
            if (counter++ == 0) {
                WSADATA wsaData = {};
                const auto iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
                if (iResult != no_error) {
                    printf("WSAStartup failed: %d\n", iResult);
                    throw sock_exception(
                        iResult, "WSAStartup failed ", platform_error_string(iResult));
                }
            }
        }
        ~winsock_manager() {
            counter--;
            if (counter == 0) {
                auto iResult = ::WSACleanup();
                if (iResult != no_error) {
                    std::cerr << "WSACleanup failed: %d\n" << std::endl;
                }
            }
        }
    };
#else
    struct winsock_manager {}; // does nothing in unix
#endif

} // namespace detail

using client_endpoint = detail::endpoint<detail::client_tag>;
using server_endpoint = detail::endpoint<detail::server_tag>;
using server_client_endpoint = detail::endpoint<detail::server_client_tag>;

// socket that wraps a platform-specific socket
template <typename ENDPOINT = client_endpoint>
class basic_socket : private detail::winsock_manager, public detail ::socket_t {

    protected:
    using ENDPOINT_TYPE = ENDPOINT;
    bool m_bactive = false;

    ENDPOINT_TYPE m_addrinfo;
    static constexpr bool is_client() {
        constexpr auto is_client = ENDPOINT::CLIENTORSERVER::is_client;
        return is_client;
    }
    static constexpr bool is_server() {
        constexpr auto is_server = ENDPOINT::CLIENTORSERVER::is_server;
        return is_server;
    }

    public:
    // constructor for all but server_client
    [[maybe_unused]] basic_socket(std::string_view host, port_t port,
        timeout_ms timeout = timeout_ms{}, blocking_type bt = blocking_type::non_blocking)
        : socket_t(), m_addrinfo{host, port} {

        // This is done in the body here, rather than in the initalizer list
        // because, for Windows, the winsock manager class needs to be constructed
        // first (and we inherit from it)
        auto skt = detail::raw_socket_helpers::create_native_socket();
        socket_t::assign_handle(skt, bt);
        (void)timeout;
        puts("basic_socket constructor complete.");
    }

    // server_client constructor
    [[maybe_unused]] basic_socket(sockets::native_socket_type s, blocking_type bt)
        : socket_t(s, bt) {
        puts("server client constructor complete");
    }

    inline friend void swap(basic_socket& lhs, basic_socket& rhs) {
        using std::swap;
        swap(rhs.m_bactive, lhs.m_bactive);
        swap(rhs.m_addrinfo, lhs.m_addrinfo);
    }
    basic_socket(basic_socket&& rhs) : socket_t(std::move(rhs)) { swap(*this, rhs); }

    basic_socket& operator=(basic_socket&& rhs) {
        swap(*this, rhs);
        return *this;
    }

    ~basic_socket() override { puts("basic_socket destructor"); }
    const addrinfo* get_addrinfo() const { return m_addrinfo; }
    auto family() const { return m_addrinfo.family(); }

    std::string_view host() const { return m_addrinfo.host(); }

    port_t port() const { return m_addrinfo.port(); }
    int close_gracefully(shutdown_options opts = shutdown_options::shut_read_write) {
        return detail::close_socket(*this, close_flags{close_flags::graceful}, opts);
    }

    // for a server, actively listening.
    // for a client: actually connected to server.
    bool is_active() const { return m_bactive; }
    bool is_connected() const {
        const auto b = (m_addrinfo.is_valid() && this->is_valid()) && is_active();
        if constexpr (is_client()) {
            return b;
        } else {
            return false;
        }
    }

    [[maybe_unused]] bool is_listening() const {
        const auto b = (m_addrinfo.is_valid() && this->is_valid()) && is_active();
        if constexpr (!is_client()) {
            return b;
        } else {
            return false;
        }
    }

    private:
    protected:
};

struct io_return_type {
    int errcode = 0;
    int return_value = 0;
};
// socket that knows how to read and write data to some endpoint:
// ENDPOINT_TYPE here is either client_endpoint or server_endpoint
template <typename CRTP, typename ENDPOINT_TYPE = client_endpoint>
class iosocket : public basic_socket<ENDPOINT_TYPE> {
    using iobase_t = basic_socket<ENDPOINT_TYPE>;

    public:
    [[maybe_unused]] iosocket(std::string_view host, port_t port,
        timeout_ms timeout = timeout_ms{}, blocking_type bt = blocking_type::non_blocking)
        : iobase_t(host, port, timeout, bt) {}

    [[maybe_unused]] iosocket(
        sockets::native_socket_type s, blocking_type bt = blocking_type::non_blocking)
        : iobase_t(s, bt) {
        puts("server client constructor complete");
    }
    ~iosocket() override = default;

    iosocket(iosocket&& rhs) : iobase_t(std::move(rhs)) {
        puts("iosocket move constructor");

    }
    iosocket& operator=(iosocket&&) = default;

    [[maybe_unused]] CRTP& derived() { return static_cast<CRTP&>(*this); }

    virtual int on_idle() noexcept {
        // single-threaded ought to pump some message loop here
        std::this_thread::yield();
        std::this_thread::sleep_for(1ms);
        return 0;
    }

    // either writes all the contents of data, or fails with reason
    // in the return type.
    io_return_type write(std::string_view data, timeout_sec timeout = {}) noexcept {
        io_return_type ret{};
        int rv = detail::sock_send_string(this->handle(), data,
            [this]() { return on_idle(); },
            [&](int64_t elapsed_ms) {
                if (elapsed_ms > timeout * 1000)
                    return (int)sockets::error_codes::error_timedout;
                else
                    return no_error;
            });
        ret.return_value = rv;
        if (rv == 0)
            ret.errcode = 0;
        else
            ret.errcode = -rv;
        return ret;
    }

    // either reads all the data available to read right now,
    // or fails with reason in the return type.
    io_return_type read(std::string& data, timeout_sec timeout = {}) noexcept {
        io_return_type ret{};
        my::timing::stopwatch_t sw;

        int rv = detail::sock_read_until(this->handle(), [&](std::string_view sdata) {
            if (!sdata.empty()) {
                data.append(sdata);
                int user_ret = do_data_arrived(data);
                if (user_ret) return user_ret;

            } else {
                const auto oi = on_idle();
                if (oi) {
                    return oi;
                }

                if (sw.elapsed_ms().count() > timeout * 1000000) {
                    return (int)sockets::error_codes::error_timedout;
                }
            }

            return 0;
        });
        ret.return_value = rv;
        ret.errcode = -rv;
        return ret;
    }

    virtual int data_arrived(std::string&) { return 0; }

    protected:
    int do_data_arrived(std::string& data) { return data_arrived(data); }
};

template <typename CRTP>
class connecting_socket : public iosocket<CRTP, client_endpoint> {
    using bsock_t = iosocket<CRTP, client_endpoint>;

    public:
    [[maybe_unused]] connecting_socket(std::string_view host, port_t port,
        timeout_ms timeout = timeout_ms{},
        blocking_type blocking = blocking_type::non_blocking)
        : bsock_t(host, port, timeout, blocking) {

        connect(timeout);
    }

    virtual ~connecting_socket() = default;

    int connect(const timeout_ms timeout = timeout_ms{}) {
        my::timing::stopwatch_t sw;

        auto ret = detail::connect_to_server(
            sw, this->handle(), this->m_addrinfo, this->is_blocking(), timeout);
        if (ret) {
            int e = ret;

            if (e != sockets::error_codes::error_timedout) e = platform_error();

            detail::close_socket(*this, close_flags{});
            if (e == sockets::error_codes::error_timedout) {

                THROW_SOCK_EXCEPTION(e, "Connect to:", this->m_addrinfo.host(), ":",
                    this->m_addrinfo.port().value, my::newline, "TIMED OUT", "after",
                    sw.elapsed_ms().count(), "ms.");
            } else {
                THROW_SOCK_EXCEPTION(e, "Connect to", this->m_addrinfo.host(), ":",
                    this->m_addrinfo.port().value, my::newline, "failed:", "after",
                    sw.elapsed_ms().count(), "ms.");
            }
        }
        if (ret == no_error) {
            this->m_bactive = true;
            CRTP& derived = static_cast<CRTP&>(*this);
            derived.on_connected();
        }

        return ret;
    }
};

using peer_info_t = detail::peer_info;
// socket that is a "connectee" of some server socket:
template <typename SERVER>
class server_client_socket : public iosocket<SERVER, server_client_endpoint> {

    SERVER& m_server;
    uint32_t m_uid = 0;
    using io_base = iosocket<SERVER, server_client_endpoint>;

    peer_info_t m_peer_info = {};

    server_client_socket& swap(server_client_socket&& rhs) {
        using std::swap;
        swap(m_server, rhs.m_server);
        swap(m_peer_info, rhs.m_peer_info);
        swap(m_uid, rhs.m_uid);
        return *this;
    }

    public:
    //         iosocket(std::string_view host, port_t port, timeout_ms timeout =
    //         timeout_ms{},
    //    blocking_type bt = blocking_type::non_blocking)

    server_client_socket(
        SERVER& server, raw_socket_handle socket, struct sockaddr in_addr, uint32_t uid)
        : io_base(socket)
        , m_server(server)
        , m_uid(uid)
        , m_peer_info(detail::get_peer_info(in_addr)) {

        assert(this->handle() == socket);
        assert(!m_peer_info.ip.empty());
        assert(m_peer_info.port.value > 0);
    }
    virtual ~server_client_socket() override {
        puts("server client destroyed");
    }

    void destroy(){
        this->close_gracefully(shutdown_options{shutdown_options::shut_read_write});
        m_server.advise_client_destroyed(*this);
        puts("client destroyed here?");
    }
    server_client_socket(server_client_socket&& rhs)
        : io_base(std::move(rhs)), m_server(rhs.m_server) {

            swap(std::move(rhs));
        }

    server_client_socket& operator=(server_client_socket&& rhs) {
        return swap(std::move(rhs));
    }
    const peer_info_t& peer_info() const { return this->m_peer_info; }

    uint32_t uid() const { return m_uid; }
    std::string m_data;

    virtual int data_arrived(std::string& data) override {
        m_data.append(data);
        m_server.client_data_arrived(*this);
        return 0;
    }
};

template <typename CRTP> class server_socket : public iosocket<CRTP, server_endpoint> {
    using io_base = iosocket<CRTP, server_endpoint>;
    using ENDPOINT_TYPE = typename io_base::ENDPOINT_TYPE;
    std::thread::id m_tid;
    //    template <typename SERVER>
    // class server_client_socket : public iosocket<SERVER, server_client_endpoint>

    public:
    using MYTYPE = server_socket<CRTP>;
    using client_type = server_client_socket<MYTYPE>;
    using client_uid_type = uint32_t;
    friend class server_client_socket<MYTYPE>;
    std::vector<client_type> m_clients;

    server_socket(std::string_view host, port_t port, bool reuse_address = true,
        backlog_type backlog = backlog_type{})
        : io_base(host.empty() ? "0.0.0.0" : host, port, timeout_ms{})
        , m_backlog(backlog)
        , m_reuse_address(reuse_address) {

        this->listen(backlog, reuse_address);
    }
    ~server_socket() override = default;

    auto reuse_address() const { return m_reuse_address; }

    // this is the thread id that run() was called on
    [[maybe_unused]] std::thread::id thread_id() const { return m_tid; }
    backlog_type m_backlog;
    backlog_type max_backlog() const { return m_backlog; }
    bool m_reuse_address = true;

    int listen(
        backlog_type backlog = backlog_type{SOMAXCONN}, bool reuse_address = true) {
        prepare_listen(backlog, reuse_address);
        bind();
        int ret = detail::listen(*this);
        if (ret == no_error)
            this->m_bactive = true;
        else
            this->m_bactive = false;
        return ret;
    }

    CRTP& crtp() { return static_cast<CRTP&>(*this); }

    template <typename CB, typename CB2> int run(CB&& on_idle, CB2&& on_new_client) {

        m_tid = std::this_thread::get_id();
        const int ret = poll(std::forward<CB>(on_idle), std::forward<CB2>(on_new_client));
        return ret;
    }

    int run() {
        m_tid = std::this_thread::get_id();
        const int ret = poll([&]() { return 0; },
            [&](auto c) { return my_on_client_connected(std::move(c)); });
        return ret;
    }

    private:
    int my_on_client_connected(client_type c) {
        auto& refc = m_clients.emplace_back(std::move(c));
        return crtp().on_client_connected(refc);
    }

    template<class ForwardIt, class UnaryPredicate>
    ForwardIt remove_one_if(ForwardIt first, ForwardIt last, UnaryPredicate p)
    {
        first = std::find_if(first, last, p);
        if (first != last)
            for(ForwardIt i = first; ++i != last; )
                if (!p(*i))
                    *first++ = std::move(*i);
        return first;
    }
    void remove_client(const client_type& c) {
        auto& v = m_clients;
        auto count = v.size();
        v.erase(remove_one_if(v.begin(), v.end(),
                    [&](const auto& cli) {
            const auto ret = cli.uid() == c.uid();
            return ret;
        }),
            v.end());

        assert(v.size() == count -1); // my remove_one_if is ok?>
    }

    protected:
    int on_client_connected(client_type c) {
        std::cout << "client connected: " << c << std::endl;
        return no_error;
    }

    // This method is just a stub. If you want to get informed when
    // a server client has some data to read, simply add this method in your
    // derived class. NOTE: it is not, and does not need to be, virtual.
    int on_client_data(client_type&) { return 0; }
    int client_data_arrived(client_type& c) { return crtp().on_client_data(c); }

    void advise_client_destroyed(const client_type& c) {
        if (crtp().on_client_destroyed(c) == 0) {
            remove_client(c);
        }
    }
    int bind() { return detail::bind(*this); }
    static inline uint32_t uid_next() {
        static uint32_t u = 0;
        return ++u;
    }
    void prepare_listen(const backlog_type& backlog, bool reuse_address) {
        m_backlog = backlog;
        m_reuse_address = reuse_address;
        const ENDPOINT_TYPE& w = this->m_addrinfo;
        if (!w) {
            set_last_error(0); // because this cock-up has nothing
            // to do with any platform error.
            THROW_SOCK_EXCEPTION("No endpoint when listen called.", newline);
        }
    }

    // TODO : these polling functions are massive and need breaking down into more
    // manageable chunks.
#ifdef _WIN32
    template <typename CB, typename CB2>
    int win32_poll_(int, INT wait_ms, CB&& on_idle, CB2&& on_new_client) {

        WSAPOLLFD fdarray;
        memset(&fdarray, 0, sizeof(WSAPOLLFD));
        fdarray.fd = this->handle();
        fdarray.events = POLLRDNORM;
        raw_socket_handle s = sockets::invalid_fd;
        int ret = 0;

        while (1) {
            if (SOCKET_ERROR == (ret = WSAPoll(&fdarray, 1, wait_ms))) {
                throw my::sockets::sock_exception(
                    platform_error(), "WSAPoll()", platform_error_string());
            }

            if (ret) {
                if (fdarray.revents & POLLRDNORM) {
                    // printf("Main: Connection established.\n");
                    struct sockaddr in_addr {};
                    socklen_t in_len = sizeof(in_addr);
                    if (INVALID_SOCKET
                        == (s = accept(this->handle(), &in_addr, &in_len))) {
                        throw my::sockets::sock_exception(
                            platform_error(), "accept() ", platform_error_string());

                    } else {

                        // ^^ blocking_type should be set there on the client,
                        // obs non-blocking for single_threaded
                        ret = on_new_client(
                            server_client_socket(*this, s, in_addr, uid_next()));
                        if (ret) return ret;
                    }
                }
            } else {
                ret = on_idle();
                if (ret) return ret;
            }
        };

        return ret;
    }

#endif

#ifdef __unix

    template <typename ON_NEW_CLIENT_CALLBACK>
    int process_events(ON_NEW_CLIENT_CALLBACK on_new_client, struct epoll_event* events,
        const int nevents) {

        int retval = no_error;
        int sfd = this->handle();

        for (int i = 0; i < nevents; i++) {
            auto efd = events[i].data.fd;
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)
                || (!(events[i].events & EPOLLIN))) {
                /* An error has occured on this fd, or the socket is not
                       ready for reading. */
                fprintf(stderr, "epoll error\n");
                close(events[i].data.fd);
                continue;
            }

            else if (sfd == efd) {
                /* We have a notification on the listening socket, which
                       means one or more incoming connections. */
                while (true) {
                    struct sockaddr in_addr {};
                    socklen_t in_len = sizeof(in_addr);
                    raw_socket_handle s = ::accept(sfd, &in_addr, &in_len);
                    if (s == invalid_sock_handle) {
                        const auto e = errno;
                        if ((e == EAGAIN) || (e == EWOULDBLOCK)) {
                            /* We have processed all incoming
                                   connections. */
                            break;
                        }
                    } else {
                        retval = on_new_client(
                            server_client_socket(*this, s, in_addr, uid_next()));

                        if (retval < 0) {
                            return retval;
                        }
                    }
                }
                continue;
            }
        }
        return retval;
    }

#endif

    template <typename CB, typename CB2> int poll(CB on_idle, CB2 on_new_client) {
#ifdef _WIN32
        return win32_poll_(
            1, 50, std::forward<CB>(on_idle), std::forward<CB2>(on_new_client));
#else
        int retval = 0;
        auto efd = epoll_create1(0);
        if (efd == -1) {
            throw_sock_exception("epoll_create1 failed");
        }

        struct epoll_event event {};
        struct epoll_event* events{nullptr};
        event.data.fd = this->handle();
        event.events = EPOLLIN | EPOLLET;
        const auto s = epoll_ctl(efd, EPOLL_CTL_ADD, this->handle(), &event);
        if (s == -1) {
            perror("epoll_ctl");
            throw_sock_exception("epoll_ctl failed");
        }

        const auto max_listeners = 1; // just get one at a time
        /* Buffer where events are returned */
        events = (epoll_event*)calloc(max_listeners, sizeof event);

        /* The event loop */
        while (true) {
            int n = 0;
            const auto iv = on_idle();
            if (iv < 0) {
                std::cerr << "on_idle() reported an error: " << iv << " Dying."
                          << std::endl;
                return iv;
            }

            const auto this_wait_time = 500;
            do {
                n = epoll_wait(efd, events, max_listeners, this_wait_time);
            } while (n < 0 && errno == EINTR);

            if (n < 0) {
                if (n != ETIMEDOUT)
                    crtp().on_info(my::strbuild(
                        "NOTE: epoll_wait returned ", n, platform_error_string()));
            }

            retval = process_events(on_new_client, events, n);
            if (retval < 0) goto done;
        }
    done:
        if (events) free(events);
        events = nullptr;
        return retval;
#endif
    }
}; // namespace my::sockets

} // namespace my::sockets
