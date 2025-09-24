#include "bmcresponder.hpp"
#include "command_line_parser.hpp"
#include "dbusproperty_watcher.hpp"
#include "provisioning_object.hpp"
#include "ssl_functions.hpp"
#include "tcp_client.hpp"
#include "tcp_server.hpp"

#include <unistd.h>

#include <nlohmann/json.hpp>

#include <fstream>
#include <iostream>
static constexpr auto SPDM_SVC = "xyz.openbmc_project.spdm";
static constexpr auto SPDM_DEVICE_PATH =
    "/xyz/openbmc_project/spdm_requester/devices/tcp/{}";
static constexpr auto SPDM_RES_PATH =
    "/xyz/openbmc_project/spdm_responder/tcp/{}";
static constexpr auto SPDM_DEVICE_INTF = "xyz.openbmc_project.SpdmDevice";
static constexpr auto SPDM_RES_INTF = "xyz.openbmc_project.SpdmResponder";
static constexpr auto SPDM_PROP = "Status";
static constexpr auto SPDM_REQ_SIGNAL = "Attested";
static constexpr auto SPDM_RES_SIGNAL = "Attested";
net::awaitable<void> waitFor(net::io_context& io_context,
                             std::chrono::seconds duration)
{
    net::steady_timer timer(io_context, duration);
    co_await timer.async_wait(net::use_awaitable);
}

net::awaitable<bool> monitorBmc(net::io_context& io_context, TcpClient& client)
{
    std::string message("Hello");
    auto [ec, bytes] = co_await client.write(net::buffer(message));
    if (ec)
    {
        LOG_ERROR("Connect error: {}", ec.message());
        co_return false;
    }
    std::array<char, 1024> data{0};
    while (true)
    {
        auto [ec, bytes] = co_await client.read(net::buffer(data));
        if (ec)
        {
            if (ec == net::error::operation_aborted)
            {
                continue;
            }
            LOG_ERROR("Receive error: {}", ec.message());
            co_return false;
        }
        std::string ping("ping");
        auto [ecw, bytesw] = co_await client.write(net::buffer(ping));
        if (ecw)
        {
            LOG_ERROR("Send error: {}", ecw.message());
            co_return false;
        }
        co_await waitFor(io_context, 1s);
    }
    co_return false;
}
net::awaitable<boost::system::error_code> connect(
    TcpClient& client, const std::string& ip, short port)
{
    int retryCount = 3;
    while (retryCount--)
    {
        auto ec = co_await client.connect(ip, std::to_string(port));

        if (ec)
        {
            if (ec.category() ==
                boost::asio::error::ssl_category) // check SSL error
            {
                LOG_ERROR("SSL connect error: {} {}", ip, ec.message());
                co_return ec;
            }

            if (retryCount <= 0)
            {
                LOG_ERROR("Connect error: {} {}", ip, ec.message());
                co_return ec;
            }

            // retry after delay
            boost::asio::steady_timer timer(
                co_await boost::asio::this_coro::executor);
            timer.expires_after(std::chrono::seconds(5));
            co_await timer.async_wait(net::use_awaitable);
            continue;
        }
        break;
    }
    co_return boost::system::error_code{};
}
net::awaitable<void> tryConnect(net::io_context& io_context,
                                const std::string& ip, short port,
                                ProvisioningController& controller)
{
    LOG_DEBUG("Trying peer connection");
    auto sslCtx = getClientContext();
    if (!sslCtx)
    {
        LOG_ERROR("ssl context is not available");
        controller.setPeerConnected(false);
        co_return;
    }
    TcpClient client(io_context.get_executor(), *sslCtx);
    auto ec = co_await connect(client, ip, port);
    if (ec)
    {
        controller.setPeerConnected(false);
        co_return;
    }
    controller.setPeerConnected(true);
    bool bmcNotResponding = co_await monitorBmc(io_context, client);
    controller.setPeerConnected(bmcNotResponding);
}

std::shared_ptr<BmcResponder> makeBmcResponder(
    net::io_context& ctx, ssl::context sslCtx, short port,
    ProvisioningController& controller)
{
    auto bmcResponder =
        std::make_shared<BmcResponder>(ctx, std::move(sslCtx), port);

    bmcResponder->onConnectionChange([&controller](bool connected) {
        controller.setPeerConnected(connected);
    });
    return bmcResponder;
}
net::awaitable<void> onSpdmStateChange(
    net::io_context& io_context, const std::string& ip, short sport,
    ProvisioningController& controller,
    std::shared_ptr<BmcResponder>& bmcResponder, short rport,
    const boost::system::error_code& ec, bool val)
{
    if (ec)
    {
        co_return;
    }
    controller.setProvisioned(val);
    if (val)
    {
        LOG_INFO("SPDM provisioning completed successfully");
        if (bmcResponder)
        {
            bmcResponder.reset();
        }
        auto sslContext = getServerContext();
        if (sslContext)
        {
            bmcResponder = makeBmcResponder(io_context, std::move(*sslContext),
                                            sport, controller);
        }
        co_return;
    }
    LOG_INFO("SPDM provisioning completed with failed status");
}
net::awaitable<void> startSpdm(
    sdbusplus::asio::connection& conn,
    std::shared_ptr<DbusSignalWatcher<bool>> watcher, net::io_context& ioc,
    const std::string& ip, short port, ProvisioningController& controller,
    std::shared_ptr<BmcResponder>& bmcResponder, short bmcport)
{
    try
    {
        // This method would start the SPDM provisioning process.
        // Implementation would depend on the specific requirements.
        LOG_INFO("Starting SPDM provisioning");
        auto device = std::format(SPDM_DEVICE_PATH, "device1");
        auto [ec, msg] =
            co_await awaitable_dbus_method_call<sdbusplus::message_t>(
                conn, SPDM_SVC, device, SPDM_DEVICE_INTF, "attest");
        if (ec)
        {
            LOG_ERROR("Failed to start spdm: {}", ec.message());
        }
        auto val = co_await watcher->watchOnce(30s);
        if (val && *val)
        {
            controller.peerProvisioned(true);
            net::co_spawn(ioc,
                          std::bind_front(tryConnect, std::ref(ioc), ip,
                                          bmcport, std::ref(controller)),
                          net::detached);
            co_return;
        }
        controller.peerProvisioned(false);
    }
    catch (std::exception& e)
    {
        LOG_ERROR("SPDM provisioning failed {}", e.what());
    }
}

int main(int argc, const char* argv[])
{
    try
    {
        auto& logger = getLogger();
        logger.setLogLevel(LogLevel::DEBUG);
        net::io_context io_context;
        std::ifstream confFile("/var/provisioning/provisioning.conf");
        auto confJson = nlohmann::json::parse(confFile);
        auto rport = confJson.value("rport", 8090);
        auto sport = confJson.value("port", 8091);
        auto ip = confJson.value("rip", std::string{"127.0.0.1"});
        cert_root = confJson.value("cert_root", std::string{"/tmp/1222/"});

        auto conn = std::make_shared<sdbusplus::asio::connection>(io_context);
        ProvisioningController controller(io_context, conn);
        conn->request_name(ProvisioningController::busName);
        std::shared_ptr<BmcResponder> bmcResponder;
        auto sslCtx = getServerContext();
        if (sslCtx)
        {
            bmcResponder = makeBmcResponder(io_context, std::move(*sslCtx),
                                            sport, controller);
        }
        controller.setProvisionHandler([&]() {
            LOG_INFO("Provisioning started");
            auto watcherPtr = std::make_shared<DbusSignalWatcher<bool>>(
                conn, SPDM_DEVICE_INTF, SPDM_REQ_SIGNAL);
            net::co_spawn(io_context,
                          std::bind_front(startSpdm, std::ref(*conn),
                                          watcherPtr, std::ref(io_context), ip,
                                          rport, std::ref(controller),
                                          std::ref(bmcResponder), sport),
                          net::detached);
        });
        controller.setCheckPeerHandler([&]() {
            LOG_INFO("Checking peer BMC connection");
            net::co_spawn(io_context,
                          std::bind_front(tryConnect, std::ref(io_context), ip,
                                          rport, std::ref(controller)),
                          net::detached);
        });

        DbusSignalWatcher<bool>::watch(
            io_context, conn,
            std::bind_front(onSpdmStateChange, std::ref(io_context), ip, sport,
                            std::ref(controller), std::ref(bmcResponder),
                            rport),
            SPDM_RES_INTF, SPDM_RES_SIGNAL);
        io_context.run();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Exception: {}", e.what());
        return 1;
    }
}
