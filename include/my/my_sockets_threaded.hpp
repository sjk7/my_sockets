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
        ~single_thread_lock_policy() { unlock(); }
        M& m_m;
    };

    template <typename M = std::mutex>
    struct single_thread_policy : single_thread_lock_policy<M> {
        using base = single_thread_lock_policy<M>;
        single_thread_policy(M& m) : base(m) {}
        template <typename T> int accept_new_client(T&&) { return 0; }
    };

    template <typename M = std::mutex> struct multi_thread_lock_policy {
        void lock() { m_m.lock(); }
        void unlock() { m_m.unlock(); }

        multi_thread_lock_policy(M& m) : m_m(m) { lock(); }
        ~multi_thread_lock_policy() { unlock(); }

        M& m_m;
    };

    template <typename T = void> struct multi_thread_impl {
        using fut_t = std::future<int>;
        using futvec_t = std::vector<fut_t>;
        futvec_t futures;
        std::thread::id m_tid;

        multi_thread_impl() : m_tid(std::this_thread::get_id()) {}
        auto& add_future(fut_t fut) {
            assert(std::this_thread::get_id() == m_tid);
            // I expect the futures collection to be accessed by the main thread.
            // If you don't like this, protect it with a lock.
            return futures.emplace_back(std::move(fut));
        }

        template <typename R>
        static inline bool future_is_ready(std::future<R> const& f) {
            bool ret = false;
            try {
                ret = f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
                assert(f.valid());
            } catch (const std::exception& e) {
                return true;
            }
            return ret;
        }
        size_t dispose_spent_futures() {
            assert(std::this_thread::get_id() == m_tid);
            const auto sz = futures.size();
            auto& vec = futures; // use shorter name
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                          [&](const auto& f) { return future_is_ready(f); }),
                vec.end());
            return sz - vec.size();
        }
    };

    template <typename M = std::mutex>
    struct multi_thread_policy : multi_thread_lock_policy<M> {
        using base = multi_thread_lock_policy<M>;
        multi_thread_policy(M& m) : base(m) {}
    };

    template <typename THREAD_POLICY, typename CRTP, size_t MAX_THREADS = 256>
    struct threaded_server : my::sockets::server_socket<CRTP> {
        using base = my::sockets::server_socket<CRTP>;
        using port_t = sockets::port_t;
        using backlog_type = sockets::backlog_type;
        using client_type = typename base::client_type;
        friend struct my::sockets::server_socket<CRTP>;
        multi_thread_impl<> m_timpl;

        threaded_server(std::string_view host, port_t port, bool reuse_address = true,
            backlog_type backlog = backlog_type{})
            : base(host, port, reuse_address, backlog) {}
        virtual ~threaded_server() {}

        protected:
        virtual void on_info(std::string_view what) { puts(what.data()); }
        static constexpr bool is_single_threaded() noexcept {
            return std::is_same_v<THREAD_POLICY, single_thread_policy<> >;
        }
        std::mutex m_client_collection_mutex;
        virtual bool can_accept_client(client_type&) noexcept {
            // check banned ips and so on:
            return true;
        }
        virtual int client_accepted(client_type c) {
            client_type* pclient = &c;
            if constexpr (is_single_threaded()) {
                return base::client_accepted(std::move(c));
            } else {
                {
                    THREAD_POLICY locker(m_client_collection_mutex);
                    pclient = &this->add_client(std::move(c));
                }
                const auto removed = m_timpl.dispose_spent_futures();
                if (removed) {
                    std::cout << "Removed " << removed << " spent futures." << std::endl;
                    std::cout << "This leaves " << m_timpl.futures.size() << " remaining."
                              << std::endl;
                }
                if (m_timpl.futures.size() >= MAX_THREADS) {
                    // it is not an error to be full up!
                    // We just simply don't accept the client.
                    return no_error;
                }

                auto& the_client = *pclient;
                m_timpl.add_future(std::async(std::launch::async, [&]() {
                    auto ret = client_has_connected(the_client);
                    std::this_thread::sleep_for(60s);
                    return ret;
                }));
                return no_error;
            }
        }

        int threaded_connect(client_type* c) { return client_has_connected(*c); }
        virtual int client_has_connected(client_type& c) {

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
            THREAD_POLICY locker(this->m_client_collection_mutex);
            std::cout << "removing client " << c << " file handle was: " << old_handle
                      << std::endl;

            return base::remove_client(c, old_handle);
        }
    };

    template <typename CRTP>
    using single_threaded_server = threaded_server<single_thread_policy<>, CRTP>;

    template <typename CRTP>
    using multi_threaded_server = threaded_server<multi_thread_policy<>, CRTP>;

} // namespace sockets
} // namespace my
