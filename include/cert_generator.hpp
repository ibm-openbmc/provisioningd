#pragma once
#include "globaldefs.hpp"
#include "logger.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <boost/asio/ssl.hpp>

#include <fstream>
#include <memory>
#include <string>
namespace NSNAME
{
// Helper for unique_ptr with OpenSSL types
template <typename T, void (*Deleter)(T*)>
using openssl_ptr = std::unique_ptr<T, decltype(Deleter)>;
using X509Ptr = openssl_ptr<X509, X509_free>;
using BIOPtr = openssl_ptr<BIO, BIO_free_all>;
X509Ptr makeX509Ptr(X509* ptr)
{
    return X509Ptr(ptr, X509_free);
}
using EVP_PKEYPtr = openssl_ptr<EVP_PKEY, EVP_PKEY_free>;
EVP_PKEYPtr makeEVPPKeyPtr(EVP_PKEY* ptr)
{
    return EVP_PKEYPtr(ptr, EVP_PKEY_free);
}
BIOPtr makeBIOPtr(BIO* ptr)
{
    return BIOPtr(ptr, BIO_free_all);
}
using EVP_PKEYPtr = openssl_ptr<EVP_PKEY, EVP_PKEY_free>;

inline void printLastError()
{
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    LOG_ERROR("OpenSSL error: {}", err_buf);
}
// Convert PEM certificate file to DER format and save to file
bool pemCertToDer(const std::string& pemPath, const std::string& derPath)
{
    FILE* pemFile = fopen(pemPath.c_str(), "r");
    if (!pemFile)
        return false;
    X509Ptr cert =
        makeX509Ptr(PEM_read_X509(pemFile, nullptr, nullptr, nullptr));
    fclose(pemFile);
    if (!cert)
        return false;

    FILE* derFile = fopen(derPath.c_str(), "wb");
    if (!derFile)
    {
        return false;
    }
    int ret = i2d_X509_fp(derFile, cert.get());
    fclose(derFile);
    return ret == 1;
}

// Convert DER certificate file to PEM format and save to file
bool derCertToPem(const std::string& derPath, const std::string& pemPath)
{
    FILE* derFile = fopen(derPath.c_str(), "rb");
    if (!derFile)
        return false;
    X509Ptr cert = makeX509Ptr(d2i_X509_fp(derFile, nullptr));
    fclose(derFile);
    if (!cert)
        return false;

    FILE* pemFile = fopen(pemPath.c_str(), "w");
    if (!pemFile)
    {
        return false;
    }
    int ret = PEM_write_X509(pemFile, cert.get());
    fclose(pemFile);
    return ret == 1;
}

// Convert PEM private key file to DER format and save to file
bool pemKeyToDer(const std::string& pemPath, const std::string& derPath)
{
    FILE* pemFile = fopen(pemPath.c_str(), "r");
    if (!pemFile)
        return false;
    EVP_PKEYPtr pkey =
        makeEVPPKeyPtr(PEM_read_PrivateKey(pemFile, nullptr, nullptr, nullptr));
    fclose(pemFile);
    if (!pkey)
        return false;

    FILE* derFile = fopen(derPath.c_str(), "wb");
    if (!derFile)
    {
        return false;
    }
    int ret = i2d_PrivateKey_fp(derFile, pkey.get());
    fclose(derFile);

    return ret == 1;
}

// Convert DER private key file to PEM format and save to file
bool derKeyToPem(const std::string& derPath, const std::string& pemPath)
{
    FILE* derFile = fopen(derPath.c_str(), "rb");
    if (!derFile)
        return false;
    EVP_PKEYPtr pkey = makeEVPPKeyPtr(d2i_PrivateKey_fp(derFile, nullptr));
    fclose(derFile);
    if (!pkey)
        return false;

    FILE* pemFile = fopen(pemPath.c_str(), "w");
    if (!pemFile)
    {
        return false;
    }
    int ret = PEM_write_PrivateKey(pemFile, pkey.get(), nullptr, nullptr, 0,
                                   nullptr, nullptr);
    fclose(pemFile);
    return ret == 1;
}
// bool loadTpm2(boost::asio::ssl::context& ctx)
// {
//     // Attempt to load certificate and private key from TPM2 using OpenSSL
//     // engine This assumes the TPM2 OpenSSL engine is installed and
//     configured
//     // Example key URI: "tpm2tss-engine:0x81010001"
//     const char* tpm2_engine_id = "tpm2tss";
//     const char* tpm2_key_id =
//         "0x81010001"; // Change as appropriate for your TPM

//     ENGINE_load_dynamic();
//     ENGINE* e = ENGINE_by_id(tpm2_engine_id);
//     if (!e)
//     {
//         LOG_ERROR("Failed to load TPM2 engine '{}'", tpm2_engine_id);
//         return false;
//     }
//     if (!ENGINE_init(e))
//     {
//         LOG_ERROR("Failed to initialize TPM2 engine");
//         ENGINE_free(e);
//         return false;
//     }

//     // Load private key from TPM2
//     EVP_PKEY* pkey = ENGINE_load_private_key(e, tpm2_key_id, nullptr,
//     nullptr); if (!pkey)
//     {
//         LOG_ERROR("Failed to load private key from TPM2");
//         ENGINE_finish(e);
//         ENGINE_free(e);
//         return false;
//     }

//     // Load certificate from file or TPM2 (usually certificate is not in
//     TPM2,
//     // so load from file)
//     FILE* certfile = fopen(ENTITY_SERVER_CERT_PATH, "r");
//     if (!certfile)
//     {
//         LOG_ERROR("Failed to open entity certificate file: {}",
//                   ENTITY_SERVER_CERT_PATH);
//         EVP_PKEY_free(pkey);
//         ENGINE_finish(e);
//         ENGINE_free(e);
//         return false;
//     }
//     X509* cert = PEM_read_X509(certfile, nullptr, nullptr, nullptr);
//     fclose(certfile);
//     if (!cert)
//     {
//         LOG_ERROR("Failed to read entity certificate from file");
//         EVP_PKEY_free(pkey);
//         ENGINE_finish(e);
//         ENGINE_free(e);
//         return false;
//     }

//     // Set certificate and private key in SSL context
//     if (SSL_CTX_use_certificate(ctx.native_handle(), cert) != 1)
//     {
//         LOG_ERROR("Failed to set certificate in SSL context");
//         X509_free(cert);
//         EVP_PKEY_free(pkey);
//         ENGINE_finish(e);
//         ENGINE_free(e);
//         return false;
//     }
//     if (SSL_CTX_use_PrivateKey(ctx.native_handle(), pkey) != 1)
//     {
//         LOG_ERROR("Failed to set private key in SSL context");
//         X509_free(cert);
//         EVP_PKEY_free(pkey);
//         ENGINE_finish(e);
//         ENGINE_free(e);
//         return false;
//     }

//     X509_free(cert);
//     EVP_PKEY_free(pkey);
//     ENGINE_finish(e);
//     ENGINE_free(e);

//     LOG_DEBUG("Loaded certificate and private key from TPM2");
//     return true;
// }
openssl_ptr<EVP_PKEY, EVP_PKEY_free> loadPrivateKey(const std::string& path,
                                                    bool pem = true)
{
    BIO* keybio = BIO_new_file(path.data(), "r");
    if (!keybio)
        return {nullptr, EVP_PKEY_free};
    EVP_PKEY* pkey{nullptr};
    if (pem)
    {
        pkey = PEM_read_bio_PrivateKey(keybio, nullptr, nullptr, nullptr);
    }
    else
    {
        pkey = d2i_PrivateKey_bio(keybio, nullptr);
    }

    BIO_free(keybio);
    return openssl_ptr<EVP_PKEY, EVP_PKEY_free>(pkey, EVP_PKEY_free);
}
openssl_ptr<X509, X509_free> loadCertificate(const std::string& path,
                                             bool pem = true)
{
    BIO* certbio = BIO_new_file(path.data(), "r");
    if (!certbio)
        return {nullptr, X509_free};
    X509* cert{nullptr};
    if (pem)
    {
        cert = PEM_read_bio_X509(certbio, nullptr, nullptr, nullptr);
    }
    else
    {
        cert = d2i_X509_bio(certbio, nullptr);
    }
    BIO_free(certbio);
    return openssl_ptr<X509, X509_free>(cert, X509_free);
}
openssl_ptr<X509_NAME, X509_NAME_free> generateX509Name(
    const std::string& common_name)
{
    openssl_ptr<X509_NAME, X509_NAME_free> name(X509_NAME_new(),
                                                X509_NAME_free);
    if (!name)
        return {nullptr, X509_NAME_free};
    X509_NAME_add_entry_by_txt(name.get(), "C", MBSTRING_ASC,
                               (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "ST", MBSTRING_ASC,
                               (const unsigned char*)"CAL", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "L", MBSTRING_ASC,
                               (const unsigned char*)"EN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "O", MBSTRING_ASC,
                               (const unsigned char*)"OpenBMC", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "OU", MBSTRING_ASC,
                               (const unsigned char*)"SPDM", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                               (const unsigned char*)common_name.data(), -1, -1,
                               0);

    return name;
}

// Generate a new EVP_PKEY (RSA 2048)
inline openssl_ptr<EVP_PKEY, EVP_PKEY_free> generate_key_pair()
{
    openssl_ptr<EVP_PKEY, EVP_PKEY_free> pkey(EVP_PKEY_new(), EVP_PKEY_free);
    openssl_ptr<RSA, RSA_free> rsa(RSA_new(), RSA_free);
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa.get(), 2048, e, nullptr);
    EVP_PKEY_assign_RSA(pkey.get(), rsa.release());
    BN_free(e);
    // pkey now contains both private and public key
    return pkey;
}
bool isSignedByCA(const openssl_ptr<X509, X509_free>& cert,
                  const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& ca_pubkey)
{
    if (!cert || !ca_pubkey)
        return false;
    // Returns 1 if signature is valid, 0 if not, -1 on error
    int result = X509_verify(cert.get(), ca_pubkey.get());
    if (result != 1)
    {
        printLastError();
        LOG_ERROR("Certificate signature verification failed");
    }
    return true;
}
// Create a new X509 certificate, signed by issuer_pkey, with subject/issuer
// names
inline openssl_ptr<X509, X509_free> create_certificate(
    EVP_PKEY* subject_key, X509_NAME* subject_name, EVP_PKEY* issuer_pkey,
    X509_NAME* issuer_name, int days_valid, bool is_ca)
{
    if (!subject_key || !subject_name || !issuer_pkey || !issuer_name)
    {
        LOG_ERROR("Invalid parameters for certificate creation");
        return makeX509Ptr(nullptr);
    }
    openssl_ptr<X509, X509_free> cert(X509_new(), X509_free);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), std::rand());
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()),
                    60L * 60L * 24L * days_valid);
    X509_set_pubkey(cert.get(), subject_key);
    X509_set_subject_name(cert.get(), subject_name);
    X509_set_issuer_name(cert.get(), issuer_name);

    X509_set_version(cert.get(), 2); // Set certificate version to v3

    // Add basicConstraints
    X509_EXTENSION* ext;
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints,
                              is_ca ? (char*)"CA:TRUE" : (char*)"CA:FALSE");
    X509_add_ext(cert.get(), ext, -1);
    X509_EXTENSION_free(ext);

    // Add keyUsage
    if (is_ca)
    {
        ext = X509V3_EXT_conf_nid(
            nullptr, nullptr, NID_key_usage,
            (char*)"keyCertSign, cRLSign, digitalSignature, keyEncipherment");
    }
    else
    {
        ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage,
                                  (char*)"digitalSignature,"
                                         " keyEncipherment");
    }
    X509_add_ext(cert.get(), ext, -1);
    X509_EXTENSION_free(ext);

    int sign_result = X509_sign(cert.get(), issuer_pkey, EVP_sha256());
    if (sign_result <= 0)
    {
        printLastError();
        LOG_ERROR("Failed to sign certificate");
        return makeX509Ptr(nullptr);
    }
    return cert;
}

// Create an intermediate CA certificate signed by root CA
inline std::pair<X509Ptr, EVP_PKEYPtr> create_ca_cert(
    EVP_PKEY* signkey, X509_NAME* signname, const std::string& common_name,
    int days_valid = 365)
{
    auto pkey = generate_key_pair();
    openssl_ptr<X509_NAME, X509_NAME_free> name = generateX509Name(common_name);
    if (!name)
    {
        LOG_ERROR("Failed to create X509 name for common name: {}",
                  common_name);
        return std::make_pair(X509Ptr(nullptr, X509_free),
                              EVP_PKEYPtr(nullptr, EVP_PKEY_free));
    }

    if (signkey)
    {
        auto ca = create_certificate(
            pkey.get(), name.get(), signkey, signname, days_valid,
            true // is_ca
        );
        return std::make_pair(std::move(ca), std::move(pkey));
    }
    auto ca = create_certificate(
        pkey.get(), name.get(), pkey.get(), name.get(), days_valid,
        true // is_ca
    );
    return std::make_pair(std::move(ca), std::move(pkey));
}

// Create an entity certificate signed by CA (root or intermediate)
inline std::pair<X509Ptr, EVP_PKEYPtr> create_leaf_cert(
    EVP_PKEY* ca_pkey, X509_NAME* ca_name, const std::string& common_name,
    int days_valid = 365)
{
    auto pkey = generate_key_pair();
    auto name = generateX509Name(common_name);

    auto cert = create_certificate(pkey.get(), name.get(), ca_pkey, ca_name,
                                   days_valid, false);
    return std::make_pair(std::move(cert), std::move(pkey));
}

bool checkValidity(const openssl_ptr<X509, X509_free>& cert)
{
    if (!cert)
    {
        LOG_ERROR("Certificate pointer is null");
        return false;
    }

    // Check validity period
    if (X509_cmp_current_time(X509_get_notBefore(cert.get())) > 0)
    {
        LOG_ERROR("Certificate is not yet valid");
        return false;
    }
    if (X509_cmp_current_time(X509_get_notAfter(cert.get())) < 0)
    {
        LOG_ERROR("Certificate has expired");
        return false;
    }

    // Check subject
    X509_NAME* subject = X509_get_subject_name(cert.get());
    if (!subject || X509_NAME_entry_count(subject) == 0)
    {
        LOG_ERROR("Certificate subject is invalid or missing");
        return false;
    }

    // Check issuer
    X509_NAME* issuer = X509_get_issuer_name(cert.get());
    if (!issuer || X509_NAME_entry_count(issuer) == 0)
    {
        LOG_ERROR("Certificate issuer is invalid or missing");
        return false;
    }

    // Check public key
    EVP_PKEY* pubkey = X509_get_pubkey(cert.get());
    if (!pubkey)
    {
        LOG_ERROR("Certificate public key is invalid or missing");
        return false;
    }
    if (EVP_PKEY_base_id(pubkey) != EVP_PKEY_RSA &&
        EVP_PKEY_base_id(pubkey) != EVP_PKEY_EC)
    {
        LOG_ERROR("Certificate public key is not RSA or EC");
        EVP_PKEY_free(pubkey);
        return false;
    }
    EVP_PKEY_free(pubkey);

    // Check serial number
    ASN1_INTEGER* serial = X509_get_serialNumber(cert.get());
    if (!serial || ASN1_INTEGER_get(serial) <= 0)
    {
        LOG_ERROR("Certificate serial number is invalid or missing");
        return false;
    }

    // Check signature algorithm
    const X509_ALGOR* sig_alg = X509_get0_tbs_sigalg(cert.get());
    if (!sig_alg)
    {
        LOG_ERROR("Certificate signature algorithm is missing");
        return false;
    }

    // Check if certificate is signed
    // if (X509_verify(cert.get(), X509_get_pubkey(cert.get())) != 1)
    // {
    //     LOG_ERROR("Certificate signature verification failed");
    //     return false;
    // }

    // Optionally check for required extensions (e.g., basicConstraints,
    // keyUsage)
    int ext_index = X509_get_ext_by_NID(cert.get(), NID_basic_constraints, -1);
    if (ext_index < 0)
    {
        LOG_ERROR("Certificate missing basicConstraints extension");
        return false;
    }

    // Optionally check version (should be v3 for most use cases)
    if (X509_get_version(cert.get()) != 2)
    {
        LOG_ERROR("Certificate version is not v3");
        return false;
    }

    return true;
}
bool saveBio(const std::string& path, const openssl_ptr<BIO, BIO_free_all>& bio)
{
    if (!bio)
    {
        LOG_ERROR("BIO pointer is null, cannot save to file {}", path);
        return false;
    }
    std::ofstream file(path);
    if (!file.is_open())
    {
        LOG_ERROR("Failed to open file {} for writing", path);
        return false;
    }
    BUF_MEM* buf;
    BIO_get_mem_ptr(bio.get(), &buf);
    file.write(buf->data, buf->length);
    file.close();
    LOG_DEBUG("BIO data saved to {}", path);
    return true;
}
openssl_ptr<BIO, BIO_free_all> loadCertificate(
    const openssl_ptr<X509, X509_free>& cert, bool pem = true)
{
    if (!checkValidity(cert))
    {
        LOG_ERROR("Certificate is not valid, cannot save to buffer");
        return makeBIOPtr(nullptr);
    }
    auto bio = makeBIOPtr(BIO_new(BIO_s_mem()));
    if (pem)
    {
        if (!PEM_write_bio_X509(bio.get(), cert.get()))
        {
            printLastError();
            LOG_ERROR("Failed to write certificate to buffer");
            return makeBIOPtr(nullptr);
        }
    }
    else
    {
        if (!i2d_X509_bio(bio.get(), cert.get()))
        {
            printLastError();
            LOG_ERROR("Failed to write certificate to buffer");
            return makeBIOPtr(nullptr);
        }
    }
    return bio;
}
bool saveCertificate(const std::string& path,
                     const openssl_ptr<X509, X509_free>& cert, bool pem = true)
{
    if (!saveBio(path, loadCertificate(cert, pem)))
    {
        LOG_ERROR("Failed to save certificate to file {}", path);
        return false;
    }
    LOG_DEBUG("Certificate saved to {}", path);
    return true;
}
bool saveCertificate(const std::string& path, const std::vector<X509*>& certs,
                     bool pem = true)
{
    if (certs.empty())
    {
        LOG_ERROR("Certificate chain is empty, nothing to save");
        return false;
    }
    openssl_ptr<BIO, BIO_free_all> bio(BIO_new(BIO_s_mem()), BIO_free_all);
    for (const auto& cert : certs)
    {
        if (!cert)
        {
            LOG_ERROR("Invalid certificate in chain, skipping");
            continue;
        }
        if (pem)
        {
            if (!PEM_write_bio_X509(bio.get(), cert))
            {
                LOG_ERROR("Failed to write certificate to BIO");
                return false;
            }
        }
        else
        {
            if (!i2d_X509_bio(bio.get(), cert))
            {
                LOG_ERROR("Failed to write certificate to BIO");
                return false;
            }
        }
    }
    return saveBio(path, std::move(bio));
}

openssl_ptr<BIO, BIO_free_all> loadPrivateKey(
    const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& pkey, bool pem = true)
{
    openssl_ptr<BIO, BIO_free_all> bio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (pem)
    {
        if (!PEM_write_bio_PrivateKey(bio.get(), pkey.get(), nullptr, nullptr,
                                      0, nullptr, nullptr))
        {
            LOG_ERROR("Failed to write private key to BIO");
            return makeBIOPtr(nullptr);
        }
    }
    else
    {
        if (!i2d_PrivateKey_bio(bio.get(), pkey.get()))
        {
            LOG_ERROR("Failed to write private key to BIO");
            return makeBIOPtr(nullptr);
        }
    }
    return bio;
}
bool savePrivateKey(const std::string& path,
                    const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& pkey,
                    bool pem = true)
{
    if (!saveBio(path, loadPrivateKey(pkey, pem)))
    {
        LOG_ERROR("Failed to save private key to file {}", path);
        return false;
    }
    LOG_DEBUG("Private key saved to {}", path);
    return true;
}
std::string toString(const openssl_ptr<X509, X509_free>& cert, bool pem = true)
{
    auto bio = loadCertificate(cert, pem);
    if (!bio)
    {
        LOG_ERROR("Failed to load certificate into BIO");
        return {};
    }

    BUF_MEM* buf;
    BIO_get_mem_ptr(bio.get(), &buf);
    return std::string(buf->data, buf->length);
}
std::string toString(const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& pkey,
                     bool pem = true)
{
    auto bio = loadPrivateKey(pkey, pem);
    if (!bio)
    {
        LOG_ERROR("Failed to load private key into BIO");
        return {};
    }
    BUF_MEM* buf;
    BIO_get_mem_ptr(bio.get(), &buf);
    return std::string(buf->data, buf->length);
}
EVP_PKEYPtr getPublicKeyFromCert(const openssl_ptr<X509, X509_free>& cert)
{
    if (!cert)
    {
        LOG_ERROR("Certificate pointer is null");
        return {nullptr, EVP_PKEY_free};
    }
    auto pkey = makeEVPPKeyPtr(X509_get_pubkey(cert.get()));
    if (!pkey)
    {
        LOG_ERROR("Failed to get public key from certificate");
    }
    return pkey;
}
std::string getPublicKeyStringFromCert(X509Ptr signcert)
{
    if (!signcert)
    {
        LOG_ERROR("Failed to read certificate from string");
        return {};
    }
    auto pkey = getPublicKeyFromCert(signcert);
    if (!pkey)
    {
        LOG_ERROR("Error: Unable to get public key from certificate.");
        return std::string();
    }
    openssl_ptr<BIO, BIO_free_all> bio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (!PEM_write_bio_PUBKEY(bio.get(), pkey.get()))
    {
        LOG_ERROR("Failed to write certificate to BIO");
        return {};
    }

    BUF_MEM* buf;
    BIO_get_mem_ptr(bio.get(), &buf);
    return std::string(buf->data, buf->length);
}
}