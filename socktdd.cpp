
#include <iostream>
#include <cassert>
#include "./include/my/my_sockets.hpp"

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif
using namespace std;

int test_low_level() {

#ifdef _WIN32
    my::sockets::detail::winsock_manager man{};
#endif

    auto test_sock = my::sockets::detail::raw_socket_helpers::create_socket();
    auto raw_sock = std::move(test_sock);
    assert(raw_sock.is_valid());
    assert(!test_sock.is_valid()); // check the moved-from socket is invalidated

    my::sockets::detail::close_socket(
        raw_sock, my::sockets::close_flags{my::sockets::close_flags::graceful});
    assert(raw_sock.handle() == my::sockets::invalid_socket);

    raw_sock = my::sockets::detail::raw_socket_helpers::create_socket();
    auto opts = my::sockets::sock_options{my::sockets::sock_options::so_rcvtimeeo};
    auto exceptions = 0;

    try {
        auto rv = my::sockets::detail::raw_socket_helpers::set_sock_opt(
            raw_sock.handle(), 1, opts);
        (void)rv;
    } catch (const my::sockets::sock_exception& e) {
        cerr << e.what() << endl;
        assert(e.errcode() == EINVAL); // true on linux
        exceptions++;
    }

#ifdef _WIN32
    assert(exceptions == 0);
#else
    assert(exceptions == 1);
#endif
    // expecting this one to succeed:
    opts = my::sockets::sock_options{my::sockets::sock_options::so_reuseaddr};
    try {
        auto rv = my::sockets::detail::raw_socket_helpers::set_sock_opt(
            raw_sock.handle(), 1, opts);
        (void)rv;
    } catch (const my::sockets::sock_exception& e) {
        cerr << e.what() << endl;
        exceptions++;
    }
#ifdef _WIN32
    assert(exceptions == 0);
#else
    assert(exceptions == 1);
#endif
    int val = 0;
    auto rv = my::sockets::detail::raw_socket_helpers::get_sock_opt(
        raw_sock.handle(), val, opts);
    assert(rv == my::sockets::no_error);
    assert(val == 1);

    my::sockets::detail::destroy_socket(raw_sock);
    assert(!raw_sock.is_valid());

    return 0;
}

class basic_skt : public my::sockets::connecting_socket<basic_skt> {
    using base_t = my::sockets::connecting_socket<basic_skt>;
    using blocking_mode = my::sockets::blocking_type;

    public:
    using timeout_ms = my::sockets::timeout_ms;
    using port_t = my::sockets::port_t;
    basic_skt(std::string_view host, port_t port, timeout_ms timeout = timeout_ms{},
        blocking_mode bm = blocking_mode::non_blocking)
        : base_t(host, port, timeout, bm) {}

    ~basic_skt() override = default;

    void on_connected() {
        cout << "basic_skt connected to: " << this->host() << ":" << this->port().value
             << endl;

        std::string data("GET / HTTP/1.0\r\n\r\n");
        auto ret = this->write(data);
        if (ret.return_value == 0) {
            std::string server_said;
            ret = this->read(server_said);
            if (ret.return_value == 0) {
                cout << "Server replied:\n" << server_said << endl;
            } else {
                assert("expected some data from google" == nullptr);
            }
        }
    }

    private:
    protected:
};

int test_basic_socket(std::string_view host, my::sockets::port_t port,
    my::sockets::timeout_ms timeout = my::sockets::timeout_ms{}) {
    using blocking_mode = my::sockets::blocking_type;
    int result = 0;

    try {
        basic_skt sck(host, port, timeout, blocking_mode::non_blocking);
        assert(sck.is_connected());
    }

    catch (const my::sockets::sock_exception& e) {
        cerr << e.what() << endl;
        result = e.errcode();
    }
    return result;
}

struct server : my::sockets::server_socket<server> {
    using server_base = my::sockets::server_socket<server>;
    using port_t = my::sockets::port_t;
    using backlog_type = my::sockets::backlog_type;

    server(std::string_view host, port_t port, bool reuse_address = true,
        backlog_type backlog = backlog_type{})
        : server_base(host, port, reuse_address, backlog) {}

    void on_info(std::string_view info) { std::cerr << info << endl; }
    int on_client_connected(client_type&& client) {

        cout << client << " connected" << endl;
        std::string d;
        auto read_result = client.read(d);
        if (read_result.errcode) {
            cerr << my::sockets::error_string(read_result.errcode) << endl;
        }
        assert(read_result.errcode
            == my::sockets::error_not_sock); // because we closed it in on_client_data
        static constexpr int quit_code = -77;
        static int ctr = 0;
        ctr++;
        if (ctr > 5) {
            return quit_code;
        }
        return my::sockets::no_error;
    }
    void on_client_destroyed(const client_type& c) { cout << c << " destroyed" << endl; }

    static inline bool crudely_detect_html_request(std::string_view d) {
        const std::string DNL = "\r\n\r\n"s;
        const auto found = d.find(DNL);
        if (found != std::string::npos) {
            return found == d.length() - 4;
        }
        return false;
    }

    int on_client_data(client_type& c) {
        auto& d = c.m_data;
        auto reply = crudely_detect_html_request(d);
        if (reply) {
            const auto you_said = "You said\r\n"s;
            auto wrote = c.write(you_said);
            assert(wrote.errcode == 0);
            wrote = c.write(d);
            assert(wrote.errcode == 0);
            auto close_result = c.close_gracefully();
            assert(close_result == my::sockets::no_error);
            return 1;
        }
        return 0;
    }
};

int test_server(std::string_view local_ip, server::port_t port) {
    int ret = 0;
    (void)ret;
    // try {
    server myserver(local_ip, port);
    cout << "myserver.active() == " << myserver.is_active() << endl;
    if (myserver.is_active()) {
        cout << "Server listening on host: " << myserver.host() << ":"
             << myserver.port().value << endl;
    }

    /*/
    myserver.run(10, [&](const auto&) { return 0; },
        [&](const auto&, auto client) {
            const auto pi = client.peer_info();
            cout << "Client " << client << " connected to server" << endl;
            return 0;
        });
    /*/
    ret = myserver.run();
    return ret;
}
int main() {
    using port_t = my::sockets::port_t;
    int ret = 0;
    (void)ret;

    ret = test_basic_socket("", port_t{80}, my::sockets::timeout_ms{2000});
#ifdef _WIN32
    assert(ret == my::sockets::error_codes::error_timedout);
#else
    assert(ret == -2); // at least on linux, it is
#endif

    test_low_level();
    ret = test_basic_socket("google.com", port_t{80});
    assert(ret == my::sockets::no_error);

    ret = test_basic_socket("some-non-existent-domain-name-no-tld", port_t{80});
#ifndef _WIN32
    assert(ret == -2);
#else
    assert(ret == WSAHOST_NOT_FOUND);
#endif

    ret = test_basic_socket("google.com", port_t{8000}, my::sockets::timeout_ms{500});
    assert(ret == my::sockets::error_codes::error_timedout);

    ret = test_server("", server::port_t{1234});
    assert(ret == -77);
}
