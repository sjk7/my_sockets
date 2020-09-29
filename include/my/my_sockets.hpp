// my_sockets.hpp
#pragma once

// my_sockets.hpp
#pragma once
#include <cstdint>
#include <cassert>
#include <atomic>
#include "my_socket_errors.h"
#include "my_sockets_utils.h"
#include <memory> // unique_ptr
#include <string>
#include <cstring>
#include <string_view>
#include <vector>
#include <thread>
#include <iostream>

#ifdef __unix
#include "my_linux_sockets_includes.hpp"
#include <sys/epoll.h>

#else
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#endif

namespace my {

namespace sockets {
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
        int value = SOMAXCONN;
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
    [[maybe_unused]] static inline bool address_family_is_valid(
        address_family fam) noexcept {
        return fam != address_family::invalid;
    }

    enum class sock_type { invalid = -1, TCP = SOCK_STREAM, DGRAM = SOCK_DGRAM };
    [[maybe_unused]] static inline bool sock_type_is_valid(sock_type st) {
        return st != sock_type::invalid;
    }

    enum class domains { af_inet = AF_INET, af_inet6 = AF_INET6 };
    enum class types { stream = SOCK_STREAM, datagram = SOCK_DGRAM };
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
        static inline constexpr uint8_t none = 0;
        static inline constexpr uint8_t immediate = 1;
        static inline constexpr uint8_t graceful = 2;
        static inline constexpr uint8_t linger_for_timeout = 4;
        uint8_t value = {immediate};
        operator uint8_t() { return value; }
    };
    struct timeout_ms {
        static constexpr uint32_t thirty_secs = 30000;
        static constexpr uint32_t default_timeout = thirty_secs;
        uint32_t value = {default_timeout};
        operator uint32_t() { return value; }
        timeout_ms() : value(default_timeout){};
        timeout_ms(const uint32_t t) : value(t) {}
    };
    struct timeout_sec {
        static constexpr uint32_t thirty_secs = 30;
        static constexpr uint32_t default_timeout = thirty_secs;
        uint32_t value = {default_timeout};
        operator uint32_t() { return value; }
        timeout_sec() : value(default_timeout){};
    };

    enum class sock_properties {
        so_invalid = 0,
        so_debug = SO_DEBUG,
        so_reuseaddr = SO_REUSEADDR,
        so_type = SO_TYPE,
        so_error = SO_ERROR,
        so_dontroute = SO_DONTROUTE,
        so_broadcast = SO_BROADCAST,
        so_sndbuf = SO_SNDBUF,
        so_recvbuf = SO_RCVBUF,
#ifdef __unix
        so_sndbuffforce = SO_SNDBUFFORCE,
        so_recvbufforce = SO_RCVBUFFORCE,
#endif
        so_keepalive = SO_KEEPALIVE,
        so_oobinline = SO_OOBINLINE,
#ifdef __unix
        so_no_check = SO_NO_CHECK,
        so_priority = SO_PRIORITY,
#endif
        so_linger = SO_LINGER,
#ifdef __unix
        so_bsdcompar = SO_BSDCOMPAT,
        so_reuseport = SO_REUSEPORT,
        so_passcred = SO_PASSCRED,
        so_peercred = SO_PEERCRED,
#endif
        so_rcvlowlat = SO_RCVLOWAT,
        so_sndlowlat = SO_SNDLOWAT,
        so_rcvtimeeo = SO_RCVTIMEO,
        so_sndtimeeo = SO_SNDTIMEO
    };

    namespace detail {
        namespace raw_socket_helpers {

            template <typename T>
            inline auto set_sock_opt(
                const raw_socket_handle h, const T optval, sock_properties optname) {

                assert(h != invalid_fd);
                const auto opt = static_cast<int>(optname);
                auto len = (socklen_t)sizeof(optval);
                //'doze requires optval as char*
                auto ret = setsockopt(h, SOL_SOCKET, opt, (const char*)&optval, len);
                if (ret != no_error) {
                    throw sock_exception(platform_error(),
                        platform_error_string(platform_error()),
                        " set_sock_opt failed.\r\n", sockets::error_string());
                }
                return ret;
            }

            template <typename T>
            inline auto get_sock_opt(
                const raw_socket_handle sock, T& what, sock_properties optname) {

                assert(sock != invalid_fd);
                auto len = (socklen_t)sizeof(what);
                // 'doze only accepts char* here
                auto ret
                    = ::getsockopt(sock, SOL_SOCKET, (int)optname, (char*)&what, &len);
                assert(ret == no_error);
                if (ret != no_error) {
                    throw my::sockets::sock_exception(platform_error(),
                        "get_sock_opt failed. Error code:",
                        sockets::platform_error_string(platform_error()), "\r\n",
                        sockets::error_string());
                }
                return ret;
            }
        } // namespace raw_socket_helpers
        struct client_tag {
            inline static constexpr bool is_server = false;
            inline static constexpr bool is_client = true;
            inline static constexpr bool is_server_client = false;
        };
        struct server_tag {
            inline static constexpr bool is_server = true;
            inline static constexpr bool is_client = false;
            inline static constexpr bool is_server_client = false;
        };

        struct server_client_tag {
            inline static constexpr bool is_server = false;
            inline static constexpr bool is_client = false;
            inline static constexpr bool is_server_client = true;
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
            port_t port() const { return m_port; }
            std::string_view host() const { return m_host; }
            address_family family() const { return this->m_family; }
            operator struct addrinfo *() const { return m_addrinfo.get(); }

            template <typename INT, typename... ARGS>
            std::string error_string(INT e, ARGS... args) {
#ifdef __unix
                std::string serr(gai_strerror(e));
                std::stringstream ss;
                ss << "endpoint error " << e << ": " << serr << ": "
                   << my::strbuild(args...);
                return std::string(ss.str());
#else
                // They reckon gai_strerror is not thread-safe in 'doze,
                // and you are better off using WSAGetLastError().
                return my::sockets::error_string(e);
#endif
            }

            bool is_valid() const { return !(m_addrinfo.get() == nullptr); }
            // create an empty endpoint object:
            endpoint() {}
            endpoint(std::string_view host, port_t port,
                address_family family = address_family::V4)
                : m_host(host), m_port(port) {
                auto ret = build(host, port, family);
                if (ret) {
                    throw sockets::sock_exception(ret, "endpoint constructor failed.");
                }
            }

            private:
            using vec_t = std::vector<std::string>;
            vec_t m_results;
            int build(std::string_view host, port_t port,
                address_family fam = address_family::V4,
                sock_type s_type = sock_type::TCP) {

                assert(address_family_is_valid(fam));
                this->m_family = fam;
                this->m_socktype = s_type;
                assert(sock_type_is_valid(s_type));
                m_addrinfo.reset(nullptr);
                m_results.clear();

                if constexpr (CLIENTORSERVER::is_server) {
                    if (host.empty()) host = "0.0.0.0";
                }

                struct addrinfo hints = prepare_hints(host, fam, s_type);
                struct addrinfo* list = {};
                auto strport = std::to_string(port.value);
                auto sport = strport.c_str();
                int ret = ::getaddrinfo(host.data(), sport, &hints, &list);
                if (ret) {
                    throw sockets::sock_exception(
                        ret, error_string(ret, m_host, ":", m_port.value));
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
                        inet_ntop(
                            AF_INET, &(((struct sockaddr_in*)sa)->sin_addr), s, maxlen);
                        break;

                    case AF_INET6:
                        inet_ntop(AF_INET6, &(((struct sockaddr_in6*)sa)->sin6_addr), s,
                            maxlen);
                        break;

                    default: strncpy(s, "Unknown AF", maxlen); return NULL;
                }

                return s;
            }

            struct addrinfo prepare_hints(std::string_view saddr = "",
                address_family af = address_family::V4,
                const sock_type st = sock_type::TCP, int flags = 0) {
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
                            throw sockets::sock_exception(-2, "Address ", saddr,
                                " is neither a valid ipv6 or ipv4 address", "");
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

        int make_blocking(const int socket, bool is_blocking) {
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
                    throw sock_exception(platform_error(), " make_blocking(",
                        want_blocking, ") failed.", platform_error_string);
                }
                assert(m_fd != 1);
                return ret;
            }
            bool is_blocking() const { return (m_blocking == blocking_type::blocking); }

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
            void assign_handle(fd_type fd) {
                assert(m_fd == invalid_fd);
                m_fd = fd;
            }
        };

        template <typename SRV>
        static inline void apply_reuse_address(const SRV& server) {
#ifndef SO_REUSEPORT
#define SO_REUSEPORT 0
#endif
            const auto reuse_address = server.reuse_address();
            int opt = 0;
            if (reuse_address) {
                opt = 1;
            }
            sock_properties props{sock_properties::so_reuseaddr};

            if (reuse_address) {
                // again, throws on error
                raw_socket_helpers::set_sock_opt(server.handle(), &opt, props);
            }
            return;
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
            const int ret
                = ::bind(server.handle(), ai->ai_addr, static_cast<socklen_t>(sz));
            if (ret != no_error) {
                throw sock_exception(platform_error(), " Bind, for host: ", server.host(),
                    ":", server.port().value, platform_error_string());
            }
            return ret;
        }

        template <typename SERVER>
        static inline int listen(const SERVER& srv, backlog_type blog = backlog_type{}) {

            int ret = ::listen(srv.handle(), blog.value);
            if (ret != no_error) {
                throw sock_exception(platform_error(),
                    "listen faled for host: ", srv.host(), ":", srv.port().value);
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

            static inline native_socket_type create_native_socket(
                blocking_type bt = blocking_type::non_blocking,
                domains domain = domains::af_inet, types type = types::stream,
                protocols protocol = protocols::Default) {

                auto sck = ::socket((int)domain, (int)type, (int)protocol);
                if (sck == invalid_fd) {
                    throw sock_exception(platform_error(),
                        " create_socket failed: ", platform_error_string());
                }
                // socket_t retval{sck, bt};
                return sck;
            }

            static inline socket_t create_socket(
                blocking_type bt = blocking_type::non_blocking,
                domains domain = domains::af_inet, types type = types::stream,
                protocols protocol = protocols::Default) {

                auto sck = ::socket((int)domain, (int)type, (int)protocol);
                if (sck == invalid_fd) {
                    throw sock_exception(platform_error(),
                        " create_socket failed: ", platform_error_string());
                }
                socket_t retval{sck, bt};
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

            l.l_linger = linger_secs.value;
            return raw_socket_helpers::set_sock_opt(sock.handle(), l,
                my::sockets::sock_properties{my::sockets::sock_properties::so_linger});
        }

        inline static auto set_sock_no_linger(socket_t& sock) {
            struct linger l = {};
            l.l_onoff = 1;
            l.l_linger = 0;
            return raw_socket_helpers::set_sock_opt(sock.handle(), l,
                sock_properties{my::sockets::sock_properties::so_linger});
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
                sock.handle(), l, sock_properties{sock_properties::so_linger});
        }
        // always closes socket, and does not throw so you can safely
        // use this in destructors.
        inline static int close_socket(socket_t& sock, close_flags flags = close_flags{},
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
                    if (error_can_continue(e, true)) {
                        if (e == EISCONN) {
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
                errno = ETIMEDOUT;
#else
                WSASetLastError(WSAETIMEDOUT);
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
            my::timing::stopwatch_t sw;
            int tot_rec = 0;

            while (true) {
                auto ret = ::recv(sck, &buf[0], BUFLEN, MSG_NOSIGNAL);
                if (ret < 0) {
                    if (!error_can_continue(e)) {
                        return -e;
                    }
                    const int predret = pred(empty_string_buf, sw.elapsed_ms().count());
                    if (predret) {
                        return predret;
                    }

                } else if (ret > 0) {
                    tot_rec += ret;
                    std::string::size_type sz = static_cast<std::string::size_type>(ret);
                    const int predret
                        = pred(std::string_view{&buf[0], sz}, sw.elapsed_ms().count());
                    if (predret) return predret;

                } else {
                    return 0; // other end closed connection here
                }
            };
            return 0;
        }

        template <typename CB, typename PRED>
        // return 0 on success (meaning we sent all the data).
        // Either we send it all, or we fail.
        static inline int sock_send_string(const raw_socket_handle sock,
            std::string_view s, CB on_send_idle, PRED pred) {
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
                        throw sock_exception(iResult, "WSAStartup failed ",
                            platform_error_string(iResult));
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
        struct winsock_manager(){};
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
        basic_socket(std::string_view host, port_t port,
            timeout_ms timeout = timeout_ms{},
            blocking_type bt = blocking_type::non_blocking)
            : socket_t(), m_addrinfo{host, port} {

            auto skt = detail::raw_socket_helpers::create_native_socket(bt);
            socket_t::assign_handle(skt);
            (void)timeout;
            puts("basic_socket constructor complete.");
        }

        // server_client constructor
        basic_socket(sockets::native_socket_type s) : socket_t(s) {
            puts("server client constructor complete");
        }

        ~basic_socket() override { puts("basic_socket destructor"); }
        const addrinfo* get_addrinfo() const { return m_addrinfo; }
        auto family() const { return m_addrinfo.family(); }

        std::string_view host() const { return m_addrinfo.host(); }

        port_t port() const { return m_addrinfo.port(); }

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
        bool is_listening() const {
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
        iosocket(std::string_view host, port_t port, timeout_ms timeout = timeout_ms{},
            blocking_type bt = blocking_type::non_blocking)
            : iobase_t(host, port, timeout, bt) {}

        iosocket(sockets::native_socket_type s) : iobase_t(s) {
            puts("server client constructor complete");
        }
        ~iosocket() override = default;

        CRTP& derived() { return static_cast<CRTP&>(*this); }

        virtual int on_idle() noexcept {
            // single-threaded ought to pump some message loop here
            return 0;
        }

        // either writes all the contents of data, or fails with reason
        // in the return type.
        io_return_type write(std::string_view data, timeout_sec timeout = {}) noexcept {
            io_return_type ret{};
            int rv = detail::sock_send_string(
                this->handle(), data, [this]() { return on_idle(); },
                [&](uint64_t elapsed_ms) {
                    if (elapsed_ms > timeout * 1000)
                        return -ETIMEDOUT;
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
            int rv = detail::sock_read_until(
                this->handle(), [&](std::string_view sdata, uint64_t elapsed_ms) {
                    data.append(sdata);
                    if (elapsed_ms > timeout * 1000) return -ETIMEDOUT;
                    return 0;
                });
            ret.return_value = rv;
            ret.errcode = -rv;
            return ret;
        }

        protected:
    };

    template <typename CRTP>
    class connecting_socket : public iosocket<CRTP, client_endpoint> {
        using bsock_t = iosocket<CRTP, client_endpoint>;

        public:
        connecting_socket(std::string_view host, port_t port,
            timeout_ms timeout = timeout_ms{},
            blocking_type blocking = blocking_type::non_blocking)
            : bsock_t(host, port, timeout, blocking) {

            connect(timeout);
        }

        virtual ~connecting_socket() {}
        int connect(const timeout_ms timeout = timeout_ms{}) {
            my::timing::stopwatch_t sw;

            auto ret = detail::connect_to_server(
                sw, this->handle(), this->m_addrinfo, this->is_blocking(), timeout);
            if (ret) {
                int e = ret;
                if (e != ETIMEDOUT) e = platform_error();

                detail::close_socket(*this, close_flags{});
                if (e == ETIMEDOUT) {
                    throw sock_exception(e, "connect to ", this->m_addrinfo.host(), ":",
                        this->m_addrinfo.port().value,
                        " failed: ", sockets::platform_error_string(e), " after ",
                        sw.elapsed_ms().count(), " ms.");
                } else {
                    throw sock_exception(e, "connect to ", this->m_addrinfo.host(), ":",
                        this->m_addrinfo.port().value,
                        " failed: ", sockets::platform_error_string(e));
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

    // socket that is a "connectee" of some server socket:
    template <typename SERVER>
    class server_client_socket : public iosocket<SERVER, server_client_endpoint> {

        const SERVER& m_server;
        uint32_t m_uid;
        using io_base = iosocket<SERVER, server_client_endpoint>;
        struct sockaddr m_in_addr = {};

        public:
        //         iosocket(std::string_view host, port_t port, timeout_ms timeout =
        //         timeout_ms{},
        //    blocking_type bt = blocking_type::non_blocking)

        server_client_socket(SERVER& server, raw_socket_handle socket,
            struct sockaddr in_addr, uint32_t uid)
            : io_base(socket), m_server(server), m_uid(uid), m_in_addr(in_addr) {

            // TODO: assign these!
            (void)socket;
            (void)in_addr;
        }
        ~server_client_socket() override = default;

        uint32_t uid() const { return m_uid; }
    };
    template <typename CRTP>
    class server_socket : public iosocket<CRTP, server_endpoint> {
        using io_base = iosocket<CRTP, server_endpoint>;
        using ENDPOINT_TYPE = typename io_base::ENDPOINT_TYPE;
        std::thread::id m_tid;

        public:
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
        std::thread::id thread_id() const { return m_tid; }
        backlog_type m_backlog;
        backlog_type max_backlog() const { return m_backlog; }
        bool m_reuse_address = true;

        int listen(
            backlog_type backlog = backlog_type{SOMAXCONN}, bool reuse_address = true) {
            this->m_backlog = backlog;
            this->m_reuse_address = reuse_address;
            const ENDPOINT_TYPE& w = this->m_addrinfo;
            if (!w) {
                throw sock_exception(-1, "no endpoint when listen called");
            }

            // throws if error, and sets the socket to reuse if required:
            bind();

            // throws if error
            int ret = detail::listen(*this);
            if (ret == no_error) this->m_bactive = true;
            return ret;
        }

        CRTP& derived() { return static_cast<CRTP&>(*this); }

        template <typename CB, typename CB2>
        int run(unsigned int max_clients, CB on_idle, CB2 on_new_client) {

            m_tid = std::this_thread::get_id();
            const int ret = poll(
                max_clients, std::forward<CB>(on_idle), std::forward<CB2>(on_new_client));
            return ret;
        }

        protected:
        int bind() { return detail::bind(*this); }
        static inline uint32_t uid_next() {
            static uint32_t u;
            return u++;
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

                            server_client_socket sc(*this, s, in_addr, uid_next());
                            // ^^ blocking_type should be set there on the client,
                            // obs non-blocking for single_threaded
                            ret = on_new_client(*this, std::move(sc));
                            if (ret) return ret;
                        }
                    }
                } else {
                    ret = on_idle(*this);
                    if (ret) return ret;
                }
            };

            return ret;
        }

#endif

        template <typename CB, typename CB2>
        int poll(int max_listeners, CB on_idle, CB2 on_new_client) {
#ifdef _WIN32
            return win32_poll_(max_listeners, 50, std::forward<CB&&>(on_idle),
                std::forward<CB2&&>(on_new_client));
#else
            int retval = 0;
            auto efd = epoll_create1(0);
            if (efd == -1) {
                perror("epoll_create");
                abort();
            }
            int sfd = this->handle();
            int s = 0;
            struct epoll_event event {};
            struct epoll_event* events{nullptr};

            event.data.fd = sfd;
            event.events = EPOLLIN | EPOLLET;
            s = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
            if (s == -1) {
                perror("epoll_ctl");
                abort();
            }

            /* Buffer where events are returned */
            events = (epoll_event*)calloc(max_listeners, sizeof event);
            my::timing::stopwatch_t sw;
            int wait_time = 5000;
            int64_t prev_wait_time = wait_time;

            unsigned int idle_count = 0;
            auto last_idle_wait_ms = 0;
            /* The event loop */
            while (true) {

                int n = 0;
                idle_count++;
                const auto iv = on_idle(*this);
                if (iv < 0) {
                    std::cerr << "on_idle() reported an error: " << iv << " Dying."
                              << std::endl;
                    return iv;
                }
                int i = 0;
                int64_t this_wait_time = wait_time;
                float ten_percent = wait_time * 0.1f;
                int iten_percent = static_cast<int>(ten_percent + 0.5f);
                if (idle_count > 2) {
                    if (abs(last_idle_wait_ms - wait_time) < iten_percent
                        && prev_wait_time > 0) {
                        this_wait_time = prev_wait_time;

                    } else {
                        // if (prev_wait_time <= 0) prev_wait_time = wait_time;
                        int64_t adj = wait_time - last_idle_wait_ms;
                        this_wait_time = prev_wait_time + adj;
                        if (this_wait_time < 0) this_wait_time = 0;
                        prev_wait_time = this_wait_time;
                    }
                    // cout << "adjusing sleep time to : " << this_wait_time << endl;
                }
                // cout << "Waiting for an event, or timeout ..." << endl;
                this_wait_time = 60000;
                do {
                    n = epoll_wait(
                        efd, events, max_listeners, static_cast<int>(this_wait_time));
                } while (n < 0 && errno == EINTR);
                // usleep(3000000);
                // cout << "epoll_wait returned: " << n << endl;
                if (n < 0) {
                    // std::cout << my::net::detail::platform_error_string(errno)
                    //         << std::endl;

                    if (n != ETIMEDOUT)
                        derived().on_info(my::strbuild(
                            "NOTE: epoll_wait returned ", n, platform_error_string()));
                }
                if (n == 0 && iv == 0) {

                    last_idle_wait_ms = (int)sw.elapsed_ms().count();
                    // std::cout << "idle path took: " << last_idle_wait_ms <<
                    // std::endl;
                    sw.reset();
                } else {
                    idle_count = 0;
                }

                for (i = 0; i < n; i++) {
                    auto efd = events[i].data.fd;
                    if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)
                        || (!(events[i].events & EPOLLIN))) {
                        /* An error has occured on this fd, or the socket is not
                           ready for reading (why were we notified then?) */
                        fprintf(stderr, "epoll error\n");
                        close(events[i].data.fd);
                        continue;
                    }

                    else if (sfd == efd) {
                        /* We have a notification on the listening socket, which
                           means one or more incoming connections. */
                        while (1) {
                            struct sockaddr in_addr {};
                            socklen_t in_len = sizeof(in_addr);
                            my::sockets::detail::make_blocking(sfd, false);
                            raw_socket_handle s = ::accept(sfd, &in_addr, &in_len);
                            if (s != invalid_sock_handle) {
                                if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                                    /* We have processed all incoming
                                       connections. */
                                    break;
                                }
                            }
                            if (s == -1) {
                                // std::cerr << "accept() returning -1" << std::endl;
                                // abort();
                                break;
                            }

                            // CTAD here: remembering server_client_socket comes
                            // from a class template, templated on us.
                            server_client_socket sc(*this, s, in_addr, uid_next());
                            // ^^ blocking_type should be set there on the client,
                            // obs non-blocking for single_threaded
                            retval = on_new_client(*this, std::move(sc));

                            if (retval < 0) {
                                goto done;
                            }
                        }
                        continue;
                    } else {
                        /* We have data on the fd waiting to be read. Read and
                           display it. We must read whatever data is available
                           completely, as we are running in edge-triggered mode
                           and won't get a notification again for the same
                           data. */
                        int done = 1;

                        if (done) {
                            printf("Closed connection on descriptor %d\n",
                                events[i].data.fd);

                            /* Closing the descriptor will make epoll remove it
                               from the set of descriptors which are monitored. */
                            close(events[i].data.fd);
                        }
                    }
                }
            }
        done:
            if (events) free(events);
            events = nullptr;
            return retval;
#endif
        }
    };

} // namespace sockets
} // namespace my