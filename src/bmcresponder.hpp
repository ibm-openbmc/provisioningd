#pragma once
#include "logger.hpp"
#include "tcp_server.hpp"

using namespace reactor;
using Streamer = reactor::TimedStreamer<ssl::stream<tcp::socket>>;
struct BmcResponder
{
    ssl::context ssl;
    TcpStreamType acceptor;
    TcpServer<TcpStreamType, BmcResponder> server;
    using WatcherCallback = std::function<void(bool)>;
    WatcherCallback watcherCallback;
    BmcResponder(net::io_context& ctx, ssl::context sslctx, short port) :
        ssl(std::move(sslctx)), acceptor(ctx.get_executor(), port, ssl),
        server(ctx.get_executor(), acceptor, *this)
    {}
    void onConnectionChange(WatcherCallback callback)
    {
        watcherCallback = std::move(callback);
    }
    net::awaitable<void> operator()(Streamer streamer)
    {
        // new connection
        watcherCallback(true);
        while (true)
        {
            std::array<char, 1024> data;
            boost::system::error_code ec;
            size_t bytes{0};
            std::tie(ec, bytes) = co_await streamer.read(net::buffer(data));
            if (ec)
            {
                if (ec == boost::asio::error::eof)
                {
                    LOG_ERROR("Error reading: {}", ec.message());
                    watcherCallback(false);
                    co_return;
                }
                if (ec == boost::asio::error::operation_aborted)
                {
                    continue;
                }
            }

            LOG_INFO("Received: {}", std::string(data.data(), bytes));
            std::string response = "alive";
            std::tie(ec, bytes) =
                co_await streamer.write(net::buffer(response));
            if (ec)
            {
                watcherCallback(false);
                co_return;
            }
        }
    }
};
