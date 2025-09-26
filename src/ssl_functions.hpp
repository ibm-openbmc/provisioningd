#pragma once
#include <boost/asio.hpp>

#include <filesystem>
static std::string cert_root = "/tmp/1222";
using namespace reactor;
namespace fs = std::filesystem;
inline std::string trusStorePath()
{
    return std::format("{}etc/ssl/certs/ca.pem", cert_root);
}
inline std::string ENTITY_CLIENT_CERT_PATH()
{
    return std::format("{}etc/ssl/certs/https/client_cert.pem", cert_root);
}
inline std::string CLIENT_PKEY_PATH()
{
    return std::format("{}etc/ssl/private/client_pkey.pem", cert_root);
}
inline std::string ENTITY_SERVER_CERT_PATH()
{
    return std::format("{}etc/ssl/certs/https/server_cert.pem", cert_root);
}
inline std::string SERVER_PKEY_PATH()
{
    return std::format("{}etc/ssl/private/server_pkey.pem", cert_root);
}
std::optional<ssl::context> getClientContext()
{
    if (fs::exists(ENTITY_CLIENT_CERT_PATH()) &&
        fs::exists(CLIENT_PKEY_PATH()) && fs::exists(trusStorePath()))
    {
        ssl::context ssl_context(ssl::context::sslv23_client);
        ssl_context.set_options(boost::asio::ssl::context::default_workarounds |
                                boost::asio::ssl::context::no_sslv2 |
                                boost::asio::ssl::context::single_dh_use);
        ssl_context.load_verify_file(trusStorePath());
        ssl_context.set_verify_mode(boost::asio::ssl::verify_peer);
        ssl_context.use_certificate_chain_file(ENTITY_CLIENT_CERT_PATH());
        ssl_context.use_private_key_file(CLIENT_PKEY_PATH(),
                                         boost::asio::ssl::context::pem);
        return std::optional<ssl::context>(std::move(ssl_context));
    }
    return std::nullopt;
}
std::optional<ssl::context> getServerContext()
{
    if (fs::exists(ENTITY_SERVER_CERT_PATH()) &&
        fs::exists(SERVER_PKEY_PATH()) && fs::exists(trusStorePath()))
    {
        ssl::context ssl_context(ssl::context::sslv23_server);
        // Load server certificate and private key
        ssl_context.set_options(boost::asio::ssl::context::default_workarounds |
                                boost::asio::ssl::context::no_sslv2 |
                                boost::asio::ssl::context::single_dh_use);

        ssl_context.use_certificate_chain_file(ENTITY_SERVER_CERT_PATH());
        ssl_context.use_private_key_file(SERVER_PKEY_PATH(),
                                         boost::asio::ssl::context::pem);
        ssl_context.load_verify_file(trusStorePath());
        ssl_context.set_verify_mode(boost::asio::ssl::verify_peer);
        return std::optional(std::move(ssl_context));
    }
    return std::nullopt;
}
