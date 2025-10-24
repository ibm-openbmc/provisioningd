#pragma once
#include "sdbus_calls.hpp"

#include <xyz/openbmc_project/Provisioning/Provisioning/server.hpp>
using namespace reactor;

using namespace sdbusplus::server::xyz::openbmc_project::provisioning;
using ProvisioningIface =
    sdbusplus::server::xyz::openbmc_project::provisioning::Provisioning;
using Ifaces = sdbusplus::server::object_t<ProvisioningIface>;
struct ProvisioningController : Ifaces
{
    net::io_context& ioContext;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    PeerConnectionStatus trustedConnectionState{
        PeerConnectionStatus::NotDetermined};
    bool provState{false};
    using PROVISIONING_HANDLER = std::function<void()>;
    PROVISIONING_HANDLER provisionHandler;

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
    void provisionPeer(std::string bmcId) override
    {
        provisionHandler();
    }
    void setProvisionHandler(PROVISIONING_HANDLER handler)
    {
        provisionHandler = std::move(handler);
    }
    PeerConnectionStatus peerConnected() const override
    {
        LOG_DEBUG("PeerConnected state {}",
                  convertPeerConnectionStatusToString(trustedConnectionState));
        return trustedConnectionState;
    }
    bool provisioned() const override
    {
        LOG_DEBUG("Provisioned state {}", provState);
        return provState;
    }
    void setPeerConnected(PeerConnectionStatus value)
    {
        LOG_DEBUG("Setting PeerConnected state {}",
                  convertPeerConnectionStatusToString(value));
        trustedConnectionState = value;
        Ifaces::peerConnected(value, false);
    }
    void setProvisioned(bool value)
    {
        LOG_DEBUG("Setting Provisioned state {}", value);
        provState = value;
        Ifaces::provisioned(value, false);
    }
};
