#pragma once
#include "sdbus_calls.hpp"
#include "xyz/openbmc_project/Provisioning/Provisioning/server.hpp"
using namespace reactor;

using namespace sdbusplus::server::xyz::openbmc_project::provisioning;
using ProvisioningIface =
    sdbusplus::server::xyz::openbmc_project::provisioning::Provisioning;
using Ifaces = sdbusplus::server::object_t<ProvisioningIface>;
struct ProvisioningController : Ifaces
{
    net::io_context& ioContext;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    // sdbusplus::asio::object_server dbusServer;
    // std::shared_ptr<sdbusplus::asio::dbus_interface> iface;
    bool trustedConnectionState{false};
    bool provState{false};
    using PROVISIONING_HANDLER = std::function<void()>;
    PROVISIONING_HANDLER provisionHandler;
    using CHECK_PEER_HANDLER = std::function<void()>;
    CHECK_PEER_HANDLER checkPeerHandler;
    static constexpr auto busName = "xyz.openbmc_project.Provisioning";
    static constexpr auto objPath = "/xyz/openbmc_project/Provisioning";
    static constexpr auto interface = Provisioning::interface;

    ProvisioningController() = delete;
    ~ProvisioningController() = default;
    ProvisioningController(const ProvisioningController&) = delete;
    ProvisioningController& operator=(const ProvisioningController&) = delete;
    ProvisioningController(ProvisioningController&&) = delete;
    ProvisioningController& operator=(ProvisioningController&&) = delete;
    ProvisioningController(net::io_context& ctx,
                           std::shared_ptr<sdbusplus::asio::connection> conn) :
        Ifaces(*conn, "/xyz/openbmc_project/Provisioning",
               Ifaces::action::defer_emit),
        ioContext(ctx), conn(conn)

    {}
    void provisionPeer() override
    {
        provision();
    }
    void initiatePeerConnectionTest() override
    {
        checkPeerHandler();
    }

    void setProvisionHandler(PROVISIONING_HANDLER handler)
    {
        provisionHandler = std::move(handler);
    }
    void setChekpeerHandler(CHECK_PEER_HANDLER handler)
    {
        checkPeerHandler = std::move(handler);
    }
    void provision()
    {
        clearProvisionData();
        provisionHandler();
    }
    void checkPeer()
    {
        checkPeerHandler();
    }

    void clearProvisionData()
    {
        // clearCertificates();
        // This method would clear the provisioning data.
        // Implementation would depend on the specific requirements.
        LOG_INFO("Clearing provisioning data");
    }
    bool peerConnected() const override
    {
        LOG_DEBUG("PeerConnected state {}", trustedConnectionState);
        return trustedConnectionState;
    }
    bool provisioned() const override
    {
        LOG_DEBUG("Provisioned state {}", provState);
        return provState;
    }
    void setPeerConnected(bool value)
    {
        LOG_DEBUG("Setting PeerConnected state {}", value);
        trustedConnectionState = value;
    }
    void setProvisioned(bool value)
    {
        LOG_DEBUG("Setting Provisioned state {}", value);
        provState = value;
    }
};
