#pragma once
#include "beastdefs.hpp"
#include "logger.hpp"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <filesystem>
#include <format>
#include <optional>
#include <string>
using namespace reactor;
namespace fs = std::filesystem;
inline std::string trustStorePath()
{
    return "/etc/ssl/certs/authority";
}
inline std::string ENTITY_CLIENT_CERT_PATH()
{
    return "/etc/ssl/certs/https/client_cert.pem";
}
inline std::string CLIENT_PKEY_PATH()
{
    return "/etc/ssl/private/client_pkey.pem";
}
inline std::string ENTITY_SERVER_CERT_PATH()
{
    return "/etc/ssl/certs/https/server_cert.pem";
}
inline std::string SERVER_PKEY_PATH()
{
    return "/etc/ssl/private/server_pkey.pem";
}
inline bool sslVerifyCallback(bool preverified,
                              boost::asio::ssl::verify_context& ctx)
{
    X509_STORE_CTX* store_ctx = ctx.native_handle();
    int err = X509_STORE_CTX_get_error(store_ctx);
    int depth = X509_STORE_CTX_get_error_depth(store_ctx);

    X509* cert = X509_STORE_CTX_get_current_cert(store_ctx);
    std::array<char, 256> subject{};
    if (cert != nullptr)
    {
        X509_NAME_oneline(X509_get_subject_name(cert), subject.data(),
                          static_cast<int>(subject.size()));
    }

    if (!preverified)
    {
        LOG_ERROR(
            "SSL certificate verification failed: depth={}, error={} ({}), subject={}",
            depth, err, X509_verify_cert_error_string(err), subject.data());
    }
    else
    {
        LOG_DEBUG("SSL certificate verification ok: depth={}, subject={}",
                  depth, subject.data());
    }
    return preverified;
}

std::optional<ssl::context> getClientContext()
{
    if (fs::exists(ENTITY_CLIENT_CERT_PATH()) &&
        fs::exists(CLIENT_PKEY_PATH()) && fs::exists(trustStorePath()))
    {
        boost::asio::ssl::context ssl_context(
            boost::asio::ssl::context::tls_client);

        // Configure the context for modern, secure operation
        ssl_context.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::no_tlsv1 |
            boost::asio::ssl::context::no_tlsv1_1);

        // Set the ciphers to only use secure, modern ones
        // This should be compatible with the server's cipher list
        SSL_CTX_set_cipher_list(
            ssl_context.native_handle(),
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

        ssl_context.add_verify_path(trustStorePath());
        ssl_context.set_verify_mode(boost::asio::ssl::verify_peer);
        ssl_context.set_verify_callback(sslVerifyCallback);
        ssl_context.use_certificate_chain_file(ENTITY_CLIENT_CERT_PATH());
        ssl_context.use_private_key_file(CLIENT_PKEY_PATH(),
                                         boost::asio::ssl::context::pem);
        return {std::move(ssl_context)};
    }
    LOG_ERROR("Client SSL context files are missing searched paths: {}, {}, {}",
              ENTITY_CLIENT_CERT_PATH(), CLIENT_PKEY_PATH(), trustStorePath());
    return std::nullopt;
}
std::optional<ssl::context> getServerContext()
{
    if (fs::exists(ENTITY_SERVER_CERT_PATH()) &&
        fs::exists(SERVER_PKEY_PATH()) && fs::exists(trustStorePath()))
    {
        // Create a context that supports TLS 1.2 and 1.3
        boost::asio::ssl::context ssl_context(
            boost::asio::ssl::context::tls_server);

        // Configure the context for modern, secure operation
        ssl_context.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::no_tlsv1 |
            boost::asio::ssl::context::no_tlsv1_1 |
            boost::asio::ssl::context::single_dh_use);

        // Set the ciphers to only use secure, modern ones
        // This is an example, you can get a list of modern ciphers from tools
        // like Mozilla SSL Config Generator
        SSL_CTX_set_cipher_list(
            ssl_context.native_handle(),
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

        ssl_context.use_certificate_chain_file(ENTITY_SERVER_CERT_PATH());
        ssl_context.use_private_key_file(SERVER_PKEY_PATH(),
                                         boost::asio::ssl::context::pem);
        ssl_context.add_verify_path(trustStorePath());
        ssl_context.set_verify_mode(
            boost::asio::ssl::verify_peer |
            boost::asio::ssl::verify_fail_if_no_peer_cert);
        ssl_context.set_verify_callback(sslVerifyCallback);
        return {std::move(ssl_context)};
    }
    return std::nullopt;
}
