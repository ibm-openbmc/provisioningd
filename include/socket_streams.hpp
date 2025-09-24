#pragma once
#include "beastdefs.hpp"
#include "logger.hpp"
#include "make_awaitable.hpp"

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/streambuf.hpp>

using namespace std::chrono_literals;
namespace NSNAME
{
struct TcpStreamType
{
    using stream_type = boost::asio::ssl::stream<tcp::socket>;
    tcp::acceptor acceptor_;
    net::any_io_executor context;
    boost::asio::ssl::context& ssl_context_;
    TcpStreamType(net::any_io_executor io_context, short port,
                  boost::asio::ssl::context& ssl_context) :
        acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
        context(io_context), ssl_context_(ssl_context)
    {}
    TcpStreamType(net::any_io_executor io_context, const std::string& ip,
                  short port, boost::asio::ssl::context& ssl_context) :
        acceptor_(io_context,
                  tcp::endpoint(boost::asio::ip::make_address(ip), port)),
        context(io_context), ssl_context_(ssl_context)
    {}

    template <typename Handler>
    void accept(Handler&& handler)
    {
        auto socket = std::make_shared<stream_type>(context, ssl_context_);
        acceptor_.async_accept(socket->lowest_layer(),
                               [this, socket, handler = std::move(handler)](
                                   boost::system::error_code ec) {
                                   if (!ec)
                                   {
                                       handler(std::move(socket));
                                   }
                               });
    }
    auto getRemoteEndpoint(stream_type& socket)
    {
        return socket.next_layer().remote_endpoint();
    }
    auto getLocalEndpoint() const
    {
        return acceptor_.local_endpoint();
    }
    void cancel()
    {
        acceptor_.cancel();
    }
};

struct UnixStreamType
{
    using stream_type =
        boost::asio::ssl::stream<boost::asio::local::stream_protocol::socket>;
    using unix_domain = boost::asio::local::stream_protocol;
    unix_domain::acceptor acceptor_;
    net::any_io_executor context;
    boost::asio::ssl::context& ssl_context_;
    UnixStreamType(net::any_io_executor io_context, const std::string& path,
                   boost::asio::ssl::context& ssl_context) :
        acceptor_(io_context,
                  boost::asio::local::stream_protocol::endpoint(path)),
        context(io_context), ssl_context_(ssl_context)
    {}

    template <typename Handler>
    void accept(Handler&& handler)
    {
        auto socket = std::make_shared<stream_type>(context, ssl_context_);
        acceptor_.async_accept(socket->lowest_layer(),
                               [this, socket, handler = std::move(handler)](
                                   boost::system::error_code ec) {
                                   if (!ec)
                                   {
                                       handler(std::move(socket));
                                   }
                               });
    }
    auto getRemoteEndpoint(stream_type& socket)
    {
        return tcp::endpoint();
    }
};

template <typename StreamType>
struct TimedStreamer
{
    TimedStreamer(std::shared_ptr<StreamType> socket,
                  std::shared_ptr<net::steady_timer> timer) :
        socket(socket), timer(timer)
    {}
    AwaitableResult<std::size_t> read(net::mutable_buffer data,
                                      bool timeout = true)
    {
        if (timeout)
        {
            setTimeout(30s);
        }
        boost::system::error_code ec;
        auto bytes = co_await socket->async_read_some(
            data, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        timer->cancel();
        co_return std::make_pair(ec, bytes);
    }
    AwaitableResult<std::size_t> readUntil(boost::asio::streambuf& buffer,
                                           const std::string& delim)
    {
        boost::system::error_code ec;
        auto bytes = co_await net::async_read_until(
            *socket, buffer, delim,
            boost::asio::redirect_error(net::use_awaitable, ec));
        co_return std::make_pair(ec, bytes);
    }
    AwaitableResult<std::string> readUntil(const std::string& delim,
                                           bool timeout = true)
    {
        boost::asio::streambuf buffer;
        if (timeout)
        {
            setTimeout(30s);
        }
        auto [ec, size] = co_await readUntil(buffer, delim);
        timer->cancel();
        if (ec)
        {
            co_return std::make_pair(ec, std::string{});
        }
        std::string ret;
        auto data = buffer.data();
        ret.append(boost::asio::buffers_begin(data),
                   boost::asio::buffers_begin(data) + size);
        co_return std::make_pair(ec, std::move(ret));

        // std::string ret;
        // ret.reserve(max_size);
        // std::array<char, 1024> data{0};
        // while (ret.length() <= max_size - delim.length())
        // {
        //     auto [ec, bytes] = co_await read(net::buffer(data), timeout);
        //     if (ec)
        //     {
        //         if (ec != boost::asio::error::eof)
        //         {
        //             LOG_DEBUG("Error reading: {}", ec.message());
        //         }
        //         co_return std::make_tuple(ec, std::move(ret));
        //     }
        //     ret.append(data.data(), bytes);
        //     if (std::string_view{data.data(), bytes}.find(delim) !=
        //         std::string::npos)
        //     {
        //         co_return std::make_tuple(boost::system::error_code{},
        //                                   std::move(ret));
        //     }
        //     std::fill(data.begin(), data.end(), 0);
        // }
        // co_return std::make_tuple(boost::system::error_code{},
        // std::move(ret));
    }

    AwaitableResult<std::size_t> write(net::const_buffer data,
                                       bool timeout = true)
    {
        if (timeout)
        {
            setTimeout(30s);
        }
        boost::system::error_code ec;
        auto bytes = co_await socket->async_write_some(
            data, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        timer->cancel();
        co_return std::make_pair(ec, bytes);
    }
    void setTimeout(std::chrono::seconds timeout)
    {
        timer->expires_after(timeout);
        timer->async_wait(
            [socket = socket](const boost::system::error_code& ec) {
                if (!ec)
                {
                    socket->next_layer().cancel();
                }
            });
    }
    void close()
    {
        boost::system::error_code ec;
        socket->next_layer().close(ec);
        if (ec)
        {
            LOG_ERROR("Error closing socket: {}", ec.message());
        }
    }
    bool isOpen() const
    {
        return socket->next_layer().is_open();
    }
    std::shared_ptr<StreamType> socket;
    std::shared_ptr<net::steady_timer> timer;
};
} // namespace NSNAME
