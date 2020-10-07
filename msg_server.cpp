// msg_server.cpp
#include "./include/my/my_sockets_threaded.hpp"
#include <iostream>
#include <algorithm>

using namespace std;

template <typename THREADTYPE>
struct test_server_t
    : my::sockets::threaded_server<THREADTYPE, test_server_t<THREADTYPE>> {
    using my_base = my::sockets::threaded_server<THREADTYPE, test_server_t<THREADTYPE>>;
    using typename my_base::backlog_type;
    using typename my_base::port_t;

    test_server_t(std::string_view host, port_t port, bool reuse_address = true,
        backlog_type backlog = backlog_type{})
        : my_base(host, port, reuse_address, backlog) {}
    virtual ~test_server_t() {}
};

int main() {
    using my::sockets::port_t;
    using my::sockets::sock_exception;
    port_t port{7000};

    cout << "--------------------" << endl;

    try {
        test_server_t<my::sockets::single_thread_policy<>> serv("", port);
        cout << "Server listening on ip: " << serv.host() << ":" << port.value << endl;
        serv.run();

    } catch (const sock_exception& e) {
        cerr << e.what() << endl;
    }
}
