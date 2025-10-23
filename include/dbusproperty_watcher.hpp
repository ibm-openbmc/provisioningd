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
    using PROPERTY_WATCHER_HANDLER = std::function<void(PropType)>;
    PROPERTY_WATCHER_HANDLER watchHandler;
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
    net::io_context& getIoContext()
    {
        return conn->get_io_context();
    }
    void startTimeout(net::steady_timer& timer, std::chrono::seconds timeout)
    {
        timer.expires_after(timeout);
        timer.async_wait([this](const boost::system::error_code& ec) {
            if (!ec)
            {
                cancelWatch();
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
            [&ctx, watcher,
             callback = std::move(callback)]() -> net::awaitable<void> {
                co_await watcher->watch([&ctx, callback = std::move(callback)](
                                            std::optional<PropType> val)
                                            -> net::awaitable<void> {
                    if (val)
                    {
                        net::co_spawn(
                            ctx,
                            [callback, val]() -> net::awaitable<void> {
                                co_await callback(boost::system::error_code{},
                                                  *val);
                            },
                            net::detached);
                        co_return;
                    }
                    LOG_DEBUG("Calling prop change with value {}", "error");
                    net::co_spawn(
                        ctx,
                        [callback, val]() -> net::awaitable<void> {
                            co_await callback(
                                boost::system::errc::make_error_code(
                                    boost::system::errc::operation_canceled),
                                PropType{});
                        },
                        net::detached);
                });
            },
            net::detached);
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
    void notifyChange(PropType value)
    {
        if (watchHandler)
        {
            watchHandler(value);
        }
    }
    void cancelWatch()
    {
        notifyChange(PropType{});
    }
};
template <typename TYPE>
struct DbusPropertyWatcher : public DbusWatcher<DbusPropertyWatcher<TYPE>, TYPE>
{
    using BASE = DbusWatcher<DbusPropertyWatcher<TYPE>, TYPE>;
    using PropType = TYPE;
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
    static std::shared_ptr<DbusPropertyWatcher<TYPE>> create(
        std::shared_ptr<sdbusplus::asio::connection> conn,
        const std::string& path, const std::string& intf,
        const std::string& prop)
    {
        return std::make_shared<DbusPropertyWatcher<TYPE>>(conn, path, intf,
                                                           prop);
    }
    void addMatch()
    {
        BASE::match.emplace(
            *BASE::conn, propMatchRule,
            std::bind_front(&DbusPropertyWatcher::handlePropertyChange, this));
    }

    void handlePropertyChange(sdbusplus::message_t& msg)
    {
        std::string interfaceName;
        std::map<std::string, std::variant<PropType>> changedProperties;
        std::vector<std::string> invalidatedProperties;

        msg.read(interfaceName, changedProperties, invalidatedProperties);

        LOG_INFO("Properties changed on interface: {}", interfaceName);

        changedProperties | std::ranges::views::filter([&](const auto& p) {
            return p.first == propName;
        });
        if (changedProperties.empty())
        {
            LOG_ERROR("Property {} not found in changed properties", propName);
            BASE::notifyChange(PropType{});
            return;
        }
        auto it = changedProperties.begin();
        if (!std::holds_alternative<PropType>(it->second))
        {
            LOG_ERROR("Property {} is not of type string", propName);
            BASE::notifyChange(PropType{});
            return;
        }
        auto result = std::get<PropType>(it->second);
        LOG_DEBUG("Property {} changed: {}", propName, result);
        BASE::notifyChange(result);
    }
};
template <typename TYPE>
struct DbusSignalWatcher : public DbusWatcher<DbusSignalWatcher<TYPE>, TYPE>
{
    using BASE = DbusWatcher<DbusSignalWatcher<TYPE>, TYPE>;
    using PropType = TYPE;

    std::string signalMatchRule;
    DbusSignalWatcher(std::shared_ptr<sdbusplus::asio::connection> conn,
                      const std::string& intf, const std::string& signal) :
        BASE(conn)

    {
        signalMatchRule = std::format(
            "type='signal',interface='{}',member='{}'", intf, signal);
        addMatch();
    }
    DbusSignalWatcher(std::shared_ptr<sdbusplus::asio::connection> conn,
                      const std::string& matchRule) : BASE(conn)

    {
        signalMatchRule = matchRule;
        addMatch();
    }
    DbusSignalWatcher(std::shared_ptr<sdbusplus::asio::connection> conn) :
        BASE(conn)
    {}
    DbusSignalWatcher& nameOwnerChanged() noexcept
    {
        signalMatchRule = sdbusplus::bus::match::rules::nameOwnerChanged();
        addMatch();
        return *this;
    }

    constexpr auto interfacesAdded() noexcept
    {
        signalMatchRule = sdbusplus::bus::match::rules::interfacesAdded();
        addMatch();
        return *this;
    }

    constexpr auto interfacesRemoved() noexcept
    {
        signalMatchRule = sdbusplus::bus::match::rules::interfacesRemoved();
        addMatch();
        return *this;
    }

    constexpr auto interfacesAdded(std::string_view p) noexcept
    {
        signalMatchRule = sdbusplus::bus::match::rules::interfacesAdded(p);
        addMatch();
        return *this;
    }

    constexpr auto interfacesAddedAtPath(std::string_view p) noexcept
    {
        signalMatchRule =
            sdbusplus::bus::match::rules::interfacesAddedAtPath(p);
        addMatch();
        return *this;
    }

    constexpr auto interfacesRemoved(std::string_view p) noexcept
    {
        signalMatchRule = sdbusplus::bus::match::rules::interfacesRemoved(p);
        addMatch();
        return *this;
    }

    constexpr auto interfacesRemovedAtPath(std::string_view p) noexcept
    {
        signalMatchRule =
            sdbusplus::bus::match::rules::interfacesRemovedAtPath(p);
        addMatch();
        return *this;
    }
    template <typename... Args>
    static std::shared_ptr<DbusSignalWatcher<TYPE>> create(
        std::shared_ptr<sdbusplus::asio::connection> conn, Args&&... args)
    {
        return std::make_shared<DbusSignalWatcher<TYPE>>(
            conn, std::forward<Args>(args)...);
    }

    void addMatch()
    {
        BASE::match.emplace(
            *BASE::conn, signalMatchRule,
            std::bind_front(&DbusSignalWatcher::hanleSignalChange, this));
    }
    void hanleSignalChange(sdbusplus::message_t& msg)
    {
        if constexpr (std::is_same_v<PropType, sdbusplus::message_t>)
        {
            BASE::notifyChange(msg);
            return;
        }
        else
        {
            PropType value;
            msg.read(value);
            LOG_DEBUG("Recieved Signal value {}", value);
            BASE::notifyChange(value);
        }
    }
};

} // namespace NSNAME
