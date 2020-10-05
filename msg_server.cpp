// msg_server.cpp
#include "./include/my/my_sockets.hpp"
#include <iostream>
#include <algorithm>

using namespace std;

struct server : my::sockets::server_socket<server> {
    using server_base = my::sockets::server_socket<server>;
    using port_t = my::sockets::port_t;
    using backlog_type = my::sockets::backlog_type;

    static constexpr size_t max_threads = 512;

    server(std::string_view host, port_t port, bool reuse_address = true,
        backlog_type backlog = backlog_type{})
        : server_base(host, port, reuse_address, backlog) {}

    void on_info(std::string_view info) { std::cerr << info << endl; }

    int on_client_connected(client_type& c) {

        cout << c << " connected" << endl;
        std::string d;
        auto read_result = c.read(d);
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
    int on_client_destroyed(const client_type& c) {
        cout << c << " destroyed." << endl;
        return 0;
    }

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
            c.destroy();
            return 1;
        }
        return 0;
    }
};

int main() {
    using my::sockets::sock_exception;

    server::port_t port{7000};
    try {
        server serv("", port);
        cout << "Server listening on ip: " << serv.host() << ":" << port.value << endl;
        serv.run();

    } catch (const sock_exception& e) {
        cerr << e.what() << endl;
    }
}
