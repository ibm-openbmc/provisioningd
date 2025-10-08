

#include "certificate_exchange.hpp"
#include "command_line_parser.hpp"
#include "eventmethods.hpp"
#include "eventqueue.hpp"
#include "logger.hpp"
#include "sdbus_calls.hpp"
#include "spdm_handshake.hpp"
#include "spdmdeviceiface.hpp"
#include "spdmresponderiface.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#include <nlohmann/json.hpp>

#include <csignal>
constexpr auto IP_EVENT = "IPEvent";
std::string prefix;
void signalHandler(int signal)
{
    if (signal == SIGTERM || signal == SIGINT)
    {
        LOG_INFO("Termination signal received, storing event queue...");
        // if (peventQueue)
        // {
        //     peventQueue->store();
        // }
        exit(0);
    }
}

void setupSignalHandlers()
{
    std::signal(SIGTERM, signalHandler);
    std::signal(SIGINT, signalHandler);
}
net::awaitable<boost::system::error_code> publisher(
    EventQueue& eventQue, Streamer streamer, const std::string& event)
{
    LOG_DEBUG("Received Event for publish: {}", event);
    auto [id, data] = parseEvent(event);
    eventQue.addEvent(makeEvent(data));
    co_return boost::system::error_code{};
}
net::awaitable<boost::system::error_code> sendEvent(
    std::shared_ptr<sdbusplus::asio::connection> conn, const std::string& id,
    Streamer streamer, const std::string& event)
{
    auto [ec, msg] = co_await awaitable_dbus_method_call<sdbusplus::message_t>(
        *conn, SpdmDeviceIface::busName,
        std::format(SpdmDeviceIface::objPath, id), SpdmDeviceIface::interface,
        "attest");
    if (ec)
    {
        LOG_ERROR("Failed to send event: {}", ec.message());
        co_return ec;
    }

    co_return boost::system::error_code{};
}
ssl::context loadServerContext(const std::string& servercert,
                               const std::string& privKey,
                               const std::string& trustStore)
{
    ssl::context ssl_server_context(ssl::context::sslv23_server);

    // Load server certificate and private key
    ssl_server_context.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::single_dh_use);
    ssl_server_context.load_verify_file(trustStore);
    ssl_server_context.set_verify_mode(boost::asio::ssl::verify_peer);
    ssl_server_context.use_certificate_chain_file(servercert);
    ssl_server_context.use_private_key_file(privKey,
                                            boost::asio::ssl::context::pem);
    return ssl_server_context;
}
void combineContexts(ssl::context& defaultCtx,
                     std::map<std::string, SSL_CTX*>& ctxMap)
{
    SSL_CTX* raw_default = defaultCtx.native_handle();

    SSL_CTX_set_client_hello_cb(
        raw_default,
        [](SSL* s, int* al, void* arg) {
            std::map<std::string, SSL_CTX*>& virtualHosts =
                *(static_cast<std::map<std::string, SSL_CTX*>*>(arg));
            const char* servername =
                SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
            if (servername)
            {
                // 2. Look up the correct SSL_CTX in your map
                auto it = virtualHosts.find(servername);
                if (it != virtualHosts.end())
                {
                    SSL_CTX* new_ctx = it->second;
                    // 3. Switch the SSL object to the new context
                    SSL_set_SSL_CTX(s, new_ctx);
                    std::cout
                        << "Switched to SSL_CTX for hostname: " << servername
                        << std::endl;
                    return SSL_CLIENT_HELLO_SUCCESS;
                }
            }
            return SSL_CLIENT_HELLO_SUCCESS;
        },
        &ctxMap);
}
void intialiseSpdmHandler(SpdmHandler& spdmHandler,
                          SpdmDeviceIface& deviceIface,
                          SpdmResponderIface& spdmResponder)
{
    spdmHandler.setSpdmFinishHandler(
        [&](bool status, bool resp) -> net::awaitable<void> {
            LOG_INFO("SPDM Handshake finished with status: {} resp {}", status,
                     resp);
            if (resp)
            {
                spdmResponder.emitStatus(status);
            }
            else
            {
                deviceIface.emitStatus(status);
            }
            co_return;
        });
}
int main(int argc, const char* argv[])
{
    auto [conf] = getArgs(parseCommandline(argc, argv), "--conf,-c");
    if (!conf)
    {
        LOG_ERROR(
            "No config file provided :eg event_broker --conf /path/to/conf");

        return 1;
    }
    try
    {
        auto json = nlohmann::json::parse(std::ifstream(conf.value().data()));

        auto servercert = json.value("server-cert", std::string{});
        auto serverprivkey = json.value("server-pkey", std::string{});
        auto clientcert = json.value("client-cert", std::string{});
        auto clientprivkey = json.value("client-pkey", std::string{});
        auto signprivkey = json.value("sign-privkey", std::string{});
        auto signcert = json.value("sign-cert", std::string{});
        auto caCert = json.value("verify-cert", std::string{});
        auto port = json.value("port", std::string{});
        auto myip = json.value("ip", std::string{"0.0.0.0"});
        auto rip = json.value("remote_ip", std::string{});
        auto rp = json.value("remote_port", std::string{});
        prefix = json.value("prefix", std::string{});
        std::vector<std::string> resources =
            json.value("resources", std::vector<std::string>{});
        auto maxConnections = 1;

        auto& logger = reactor::getLogger();
        logger.setLogLevel(reactor::LogLevel::DEBUG);
        net::io_context io_context;

        ssl::context ssl_client_context(ssl::context::sslv23_client);
        ssl_client_context.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::single_dh_use);
        ssl_client_context.load_verify_file(caCert);
        ssl_client_context.set_verify_mode(boost::asio::ssl::verify_peer);
        ssl_client_context.use_certificate_chain_file(clientcert);
        ssl_client_context.use_private_key_file(clientprivkey,
                                                boost::asio::ssl::context::pem);
        auto serverCtx = loadServerContext(servercert, serverprivkey, caCert);
        TcpStreamType acceptor(io_context.get_executor(), myip,
                               std::atoi(port.data()), serverCtx);
        EventQueue eventQueue(io_context.get_executor(), acceptor,
                              ssl_client_context, maxConnections);
        auto conn = std::make_shared<sdbusplus::asio::connection>(io_context);

        eventQueue.addEventConsumer(
            "Publish", std::bind_front(publisher, std::ref(eventQueue)));
        // eventQueue.load();
        setupSignalHandlers();
        auto verifyCert = loadCertificate(signcert);
        if (!verifyCert)
        {
            LOG_ERROR("Failed to load signing certificate from {}", signcert);
            return 1;
        }
        CertificateExchanger::createCertificates();
        SpdmHandler spdmHandler(
            MeasurementTaker(loadPrivateKey(signprivkey)),
            MeasurementVerifier(getPublicKeyFromCert(verifyCert)), eventQueue,
            io_context);
        for (const auto& resource : resources)
        {
            spdmHandler.addToMeasure(resource);
        }
        sdbusplus::asio::object_server dbusServer(conn);
        SpdmDeviceIface::ResponderInfo responderInfo{"device1", rip.data(),
                                                     rp.data()};
        eventQueue.addEventConsumer(
            "ATTEST", std::bind_front(sendEvent, conn, responderInfo.id));
        SpdmDeviceIface spdmDevice(conn, dbusServer, responderInfo,
                                   spdmHandler);
        SpdmResponderIface spdmResponder(conn, dbusServer, "responder1");
        intialiseSpdmHandler(spdmHandler, spdmDevice, spdmResponder);

        conn->request_name(SpdmDeviceIface::busName);
        io_context.run();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Exception: {}", e.what());
    }
    return 0;
}
