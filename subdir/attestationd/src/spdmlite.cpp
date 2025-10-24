

#include "certificate_exchange.hpp"
#include "command_line_parser.hpp"
#include "dbusproperty_watcher.hpp"
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
static constexpr auto LLDP_SVC = "xyz.openbmc_project.LLDP";
static constexpr auto LLDP_PATH = "/xyz/openbmc_project/network/lldp/{}";
static constexpr auto LLDP_INTF = "xyz.openbmc_project.Network.LLDP.TLVs";
static constexpr auto LLDP_PROP = "ManagementAddressIPv4";
static constexpr auto LLDP_REC_PATH =
    "/xyz/openbmc_project/network/lldp/{}/receive";
std::string prefix;
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

net::awaitable<void> onNeighbhorFound(
    net::io_context& io_context,
    std::shared_ptr<sdbusplus::asio::connection> conn,
    sdbusplus::asio::object_server& dbusServer, SpdmHandler& spdmHandler,
    SpdmResponderIface& spdmResponder,
    std::shared_ptr<SpdmDeviceIface>& spdmDevice, const std::string& remotePort,
    const boost::system::error_code& ec, const std::string& propVal)
{
    LOG_INFO("Neighbour LLDP ManagementAddressIPv4 changed: {}", propVal);
    SpdmDeviceIface::ResponderInfo responderInfo{"device1", propVal,
                                                 remotePort};
    spdmDevice.reset();
    spdmDevice = std::make_shared<SpdmDeviceIface>(conn, dbusServer,
                                                   responderInfo, spdmHandler);
    intialiseSpdmHandler(spdmHandler, *spdmDevice, spdmResponder);
    co_return;
}
net::awaitable<void> updateNeighbourDetails(
    net::io_context& io_context,
    std::shared_ptr<sdbusplus::asio::connection> conn,
    sdbusplus::asio::object_server& dbusServer, SpdmHandler& spdmHandler,
    SpdmResponderIface& spdmResponder,
    std::shared_ptr<SpdmDeviceIface>& spdmDevice, const std::string& remotePort)

{
    auto [ec, propVal] = co_await getProperty<std::string>(
        *conn, LLDP_SVC, std::format(LLDP_REC_PATH, "eth1"), LLDP_INTF,
        LLDP_PROP);
    if (ec)
    {
        LOG_ERROR("Failed to get LLDP property: {}", ec.message());
        co_return;
    }
    LOG_INFO("LLDP ManagementAddressIPv4: {}", propVal);
    SpdmDeviceIface::ResponderInfo responderInfo{"device1", propVal,
                                                 remotePort};
    spdmDevice = std::make_shared<SpdmDeviceIface>(conn, dbusServer,
                                                   responderInfo, spdmHandler);
    intialiseSpdmHandler(spdmHandler, *spdmDevice, spdmResponder);
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
        std::shared_ptr<SpdmDeviceIface> spdmDevice;
        SpdmResponderIface spdmResponder(conn, dbusServer, "responder1");
        DbusPropertyWatcher<std::string>::watch(
            io_context, conn,
            std::bind_front(onNeighbhorFound, std::ref(io_context), conn,
                            std::ref(dbusServer), std::ref(spdmHandler),
                            std::ref(spdmResponder), std::ref(spdmDevice), rp),
            std::format(LLDP_REC_PATH, "eth1"), LLDP_INTF, LLDP_PROP);

        net::co_spawn(
            io_context,
            std::bind_front(updateNeighbourDetails, std::ref(io_context), conn,
                            std::ref(dbusServer), std::ref(spdmHandler),
                            std::ref(spdmResponder), std::ref(spdmDevice), rp),
            net::detached);
        conn->request_name(SpdmDeviceIface::busName);
        io_context.run();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Exception: {}", e.what());
    }
    return 0;
}
