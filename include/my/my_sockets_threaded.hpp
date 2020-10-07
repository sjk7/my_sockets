// my_sockets_threaded.hpp
#pragma once
#include "my_sockets.hpp"
#include <future>
#include <thread>
#include <mutex>

namespace my {
namespace sockets {

    template <typename M = std::mutex> struct single_thread_lock_policy {
        void lock() {} // does nothing
        void unlock() {} // does nothing

        single_thread_lock_policy(M& m) : m_m(m) { lock(); }
        single_thread_lock_policy() { unlock(); }
        M& m_m;
    };

    template <typename M = std::mutex>
    struct single_thread_policy : single_thread_lock_policy<M> {
        using base = single_thread_lock_policy<M>;
        single_thread_policy(M& m) : base(m) {}
        template <typename T> int accepted_new_client(T&&) { return 0; }
    };

    template <typename M = std::mutex>
    struct multi_threaded_lock_policy : std::lock_guard<M> {};

    template <typename LOCK_POLICY, typename CRTP>
    struct threaded_server : my::sockets::server_socket<CRTP> {
        using base = my::sockets::server_socket<CRTP>;
        using port_t = sockets::port_t;
        using backlog_type = sockets::backlog_type;
        using client_type = typename base::client_type;
        friend struct my::sockets::server_socket<CRTP>;

        threaded_server(std::string_view host, port_t port, bool reuse_address = true,
            backlog_type backlog = backlog_type{})
            : base(host, port, reuse_address, backlog) {}
        virtual ~threaded_server() {}

        protected:
        virtual void on_info(std::string_view what) { puts(what.data()); }
        constexpr bool is_single_threaded() noexcept {
            return std::is_same_v<LOCK_POLICY, single_thread_policy<> >;
        }
        std::mutex m_client_collection_mutex;
        virtual bool can_accept_client(client_type&) noexcept {
            // check banned ips and so on:
            return true;
        }
        virtual int client_accepted(client_type c) {
            if (is_single_threaded()) {
                return base::client_accepted(std::move(c));
            }
            LOCK_POLICY locker(m_client_collection_mutex);
            auto& refc = this->add_client(std::move(c));
            return client_has_connected(refc);
        }
        virtual int client_has_connected(client_type& c) {
            // wait for data here, and so on
            std::string d;
            auto read_result = c.read(d);
            assert(read_result.errcode == error_not_sock);
            // we closed it whilst reading, so ok

            return no_error;
        }

        virtual int data_arrived(client_type& c) {
            auto& d = c.m_data;
            c.write("Your file descriptor is: ");
            c.write(std::to_string(c.handle()).c_str());
            c.write(NL);
            time_t rawtime;
            struct tm* timeinfo;
            char buffer[80] = {0};

            time(&rawtime);
            timeinfo = localtime(&rawtime);

            strftime(buffer, 80, "Now it's %T", timeinfo);
            c.write(buffer);
            c.write(DNL);
            if (crudely_detect_html_request(d)) {
                c.write("Hello, HTML client! You said:");

            } else {
                c.write("Hello non-html client! You said:");
            }
            c.write(DNL);
            c.write(d);
            c.write(DNL);
            c.write(DNL);
            c.destroy();

            return 0;
        }

        virtual void advise_client_destroyed(
            client_type& c, native_socket_type old_handle) {
            remove_client(c, old_handle);
        }

        virtual void remove_client(const client_type& c, native_socket_type old_handle) {
            LOCK_POLICY locker(this->m_client_collection_mutex);
            std::cout << "removing client " << c << " file handle was: " << old_handle
                      << std::endl;

            return base::remove_client(c, old_handle);
        }
    };

    template <typename CRTP>
    using single_threaded_server = threaded_server<single_thread_lock_policy<>, CRTP>;

    template <typename CRTP>
    using multi_threaded_server = threaded_server<multi_threaded_lock_policy<>, CRTP>;

} // namespace sockets
} // namespace my
