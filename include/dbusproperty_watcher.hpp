#pragma once
#include "logger.hpp"
#include "sdbus_calls.hpp"
#include "utilities.hpp"

#include <chrono>
#include <ranges>
namespace NSNAME
{
template <typename Handler, typename PropType>
concept WatchHandler =
    requires(Handler handler, const boost::system::error_code& ec,
             PropType result) {
        { handler(ec, result) } -> std::same_as<boost::asio::awaitable<void>>;
    };

template <typename Derived, typename PropType>
struct DbusWatcher
{
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::optional<sdbusplus ::bus::match::match> match;

    DbusWatcher() = delete;
    DbusWatcher(const DbusWatcher&) = delete;
    DbusWatcher& operator=(const DbusWatcher&) = delete;
    DbusWatcher(DbusWatcher&&) = delete;
    DbusWatcher& operator=(DbusWatcher&&) = delete;
    DbusWatcher(std::shared_ptr<sdbusplus::asio::connection> conn) : conn(conn)
    {}

    Derived& derived()
    {
        return static_cast<Derived&>(*this);
    }
    void startTimeout(net::steady_timer& timer, std::chrono::seconds timeout)
    {
        timer.expires_after(timeout);
        timer.async_wait([this](const boost::system::error_code& ec) {
            if (!ec)
            {
                derived().cancelWatch();
                LOG_ERROR(
                    "Timeout occurred while waiting for SPDM property change");
            }
        });
    }
    net::awaitable<void> watch(auto callback)
    {
        boost::system::error_code ec{};
        while (!ec)
        {
            auto h = derived().makeWatchHandler();
            PropType res{};
            std::tie(ec, res) = co_await h();
            LOG_DEBUG("after  watch");
            co_await callback(std::optional(res));
        }
        LOG_ERROR("Error in watching Dbus: {}", ec.message());
        co_await callback(std::nullopt);
        co_return;
    }
    net::awaitable<std::optional<PropType>> watchOnce(
        std::chrono::seconds timeout = 1s)
    {
        auto h = derived().makeWatchHandler();
        net::steady_timer timer(conn->get_io_context());
        startTimeout(timer, timeout);
        auto [ec, res] = co_await h();
        timer.cancel(); // Cancel the timer if we got a response
        if (ec)
        {
            LOG_ERROR("Error in watching Dbus: {}", ec.message());
            co_return std::nullopt;
        }
        co_return std::optional(res);
    }
    template <typename... Args>
    static void watch(net::io_context& ctx,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      WatchHandler<PropType> auto callback, Args... args)
    {
        auto watcher = Derived::create(conn, args...);
        net::co_spawn(
            ctx,
            [watcher,
             callback = std::move(callback)]() -> net::awaitable<void> {
                co_await watcher->watch([callback = std::move(callback)](
                                            std::optional<PropType> val)
                                            -> net::awaitable<void> {
                    if (val)
                    {
                        LOG_DEBUG("Calling  Dbus event with value {}", *val);
                        co_await callback(boost::system::error_code{}, *val);
                        co_return;
                    }
                    LOG_DEBUG("Calling prop change with value {}", "error");
                    co_await callback(
                        boost::system::errc::make_error_code(
                            boost::system::errc::operation_canceled),
                        PropType{});
                });
            },
            net::detached);
    }
};
template <typename TYPE>
struct DbusPropertyWatcher : public DbusWatcher<DbusPropertyWatcher<TYPE>, TYPE>
{
    using BASE = DbusWatcher<DbusPropertyWatcher<TYPE>, TYPE>;
    using PropType = TYPE;
    using PROP_WATCHER_HANDLER = std::function<void(PropType)>;
    PROP_WATCHER_HANDLER watchHandler;
    std::string propMatchRule;
    std::string propName;
    DbusPropertyWatcher(std::shared_ptr<sdbusplus::asio::connection> conn,
                        const std::string& path, const std::string& intf,
                        const std::string& prop) : BASE(conn), propName(prop)
    {
        propMatchRule =
            sdbusplus::bus::match::rules::propertiesChanged(path, intf);
        addMatch();
    }
    void setWatchHandler(PROP_WATCHER_HANDLER handler)
    {
        watchHandler = std::move(handler);
    }
    static std::shared_ptr<DbusPropertyWatcher<TYPE>> create(
        std::shared_ptr<sdbusplus::asio::connection> conn,
        const std::string& path, const std::string& intf,
        const std::string& prop)
    {
        return std::make_shared<DbusPropertyWatcher<TYPE>>(conn, path, intf,
                                                           prop);
    }
    void cancelWatch()
    {
        watchHandler(PropType{});
    }
    void addMatch()
    {
        BASE::match.emplace(
            *BASE::conn, propMatchRule,
            std::bind_front(&DbusPropertyWatcher::handlePropertyChange, this));
    }
    auto makeWatchHandler()
    {
        return make_awaitable_handler<PropType>([this](auto promise) {
            auto promise_ptr =
                std::make_shared<decltype(promise)>(std::move(promise));

            watchHandler = [promise_ptr](PropType status) {
                promise_ptr->setValues(boost::system::error_code{}, status);
            };
        });
    }
    void handlePropertyChange(sdbusplus::message_t& msg)
    {
        std::string interfaceName;
        std::map<std::string, std::variant<bool>> changedProperties;
        std::vector<std::string> invalidatedProperties;

        msg.read(interfaceName, changedProperties, invalidatedProperties);

        LOG_INFO("Properties changed on interface: {}", interfaceName);

        changedProperties | std::ranges::views::filter([&](const auto& p) {
            return p.first == propName;
        });
        if (changedProperties.empty())
        {
            LOG_ERROR("Property {} not found in changed properties", propName);
            watchHandler(PropType{});
            return;
        }
        auto it = changedProperties.begin();
        if (!std::holds_alternative<PropType>(it->second))
        {
            LOG_ERROR("Property {} is not of type string", propName);
            watchHandler(PropType{});
            return;
        }
        auto result = std::get<PropType>(it->second);
        LOG_DEBUG("Property {} changed: {}", propName, result);
        watchHandler(result);
    }
};
template <typename TYPE>
struct DbusSignalWatcher : public DbusWatcher<DbusSignalWatcher<TYPE>, TYPE>
{
    using BASE = DbusWatcher<DbusSignalWatcher<TYPE>, TYPE>;
    using PropType = TYPE;
    using SIGNAL_WATCHER_HANDLER = std::function<void(PropType)>;
    SIGNAL_WATCHER_HANDLER watchHandler;
    std::string signalMatchRule;
    std::string signalName;
    DbusSignalWatcher(std::shared_ptr<sdbusplus::asio::connection> conn,
                      const std::string& intf, const std::string& signal) :
        BASE(conn), signalName(signal)

    {
        signalMatchRule = std::format(
            "type='signal',interface='{}',member='{}'", intf, signalName);
        addMatch();
    }
    static std::shared_ptr<DbusSignalWatcher<TYPE>> create(
        std::shared_ptr<sdbusplus::asio::connection> conn,
        const std::string& intf, const std::string& signal)
    {
        return std::make_shared<DbusSignalWatcher<TYPE>>(conn, intf, signal);
    }
    void setWatchHandler(SIGNAL_WATCHER_HANDLER handler)
    {
        watchHandler = std::move(handler);
    }
    void cancelWatch()
    {
        watchHandler(PropType{});
    }

    auto makeWatchHandler()
    {
        return make_awaitable_handler<PropType>([this](auto promise) {
            auto promise_ptr =
                std::make_shared<decltype(promise)>(std::move(promise));

            watchHandler = [promise_ptr](PropType status) {
                promise_ptr->setValues(boost::system::error_code{}, status);
            };
        });
    }
    void addMatch()
    {
        BASE::match.emplace(
            *BASE::conn, signalMatchRule,
            std::bind_front(&DbusSignalWatcher::hanleSignalChange, this));
    }
    void hanleSignalChange(sdbusplus::message_t& msg)
    {
        PropType value;
        msg.read(value);
        LOG_DEBUG("Recieved Signal value {}", value);
        watchHandler(value);
    }
};

} // namespace NSNAME
