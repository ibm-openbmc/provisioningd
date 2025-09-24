#pragma once
#include "make_awaitable.hpp"

#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/asio/sd_event.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/timer.hpp>
namespace NSNAME
{
template <typename... RetTypes, typename... InputArgs>
inline auto awaitable_dbus_method_call(
    sdbusplus::asio::connection& conn, const std::string& service,
    const std::string& objpath, const std::string& interf,
    const std::string& method, const InputArgs&... a)
    -> AwaitableResult<RetTypes...>
{
    auto h = make_awaitable_handler<RetTypes...>([&](auto promise) {
        conn.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           RetTypes... values) mutable {
                promise.setValues(ec, std::move(values)...);
            },
            service, objpath, interf, method, a...);
    });
    co_return co_await h();
}

template <typename Type>
inline AwaitableResult<Type> getProperty(
    sdbusplus::asio::connection& conn, const std::string& service,
    const std::string& objpath, const std::string& interf,
    const std::string& property)
{
    auto [ec, value] =
        co_await awaitable_dbus_method_call<std::variant<std::monostate, Type>>(
            conn, service, objpath, "org.freedesktop.DBus.Properties", "Get",
            interf, property);
    if (ec)
    {
        co_return ReturnTuple<Type>{ec, Type{}};
    }
    if (!std::holds_alternative<Type>(value))
    {
        LOG_ERROR("Error getting property: Type miss match");
        co_return ReturnTuple<Type>{ec, Type{}};
    }
    co_return ReturnTuple<Type>{ec, std::get<Type>(value)};
}

template <typename InputArgs>
inline AwaitableResult<boost::system::error_code> setProperty(
    sdbusplus::asio::connection& conn, const std::string& service,
    const std::string& objpath, const std::string& interf,
    const std::string& property, const InputArgs& value)
{
    auto h =
        make_awaitable_handler<boost::system::error_code>([&](auto promise) {
            sdbusplus::asio::setProperty(
                conn, service, objpath, interf, property, value,
                [promise = std::move(promise)](
                    boost::system::error_code ec) mutable {
                    promise.setValues(ec);
                });
        });
    co_return co_await h();
}

template <typename VariantType>
inline AwaitableResult<std::vector<std::pair<std::string, VariantType>>>
    getAllProperties(sdbusplus::asio::connection& bus,
                     const std::string& service, const std::string& path,
                     const std::string& interface)
{
    using ReturnType = std::vector<std::pair<std::string, VariantType>>;
    auto h = make_awaitable_handler<ReturnType>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           const ReturnType& data) mutable {
                promise.setValues(ec, data);
            },
            service, path, "org.freedesktop.DBus.Properties", "GetAll",
            interface);
    });
    co_return co_await h();
}

template <typename SubTreeType>
inline AwaitableResult<SubTreeType> getSubTree(
    sdbusplus::asio::connection& bus, const std::string& path, int depth,
    const std::vector<std::string>& interfaces = {})
{
    auto h = make_awaitable_handler<SubTreeType>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           SubTreeType subtree) mutable {
                promise.setValues(ec, std::move(subtree));
            },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTree", path, depth,
            interfaces);
    });
    co_return co_await h();
}

template <typename Dict>
inline AwaitableResult<Dict> getObjects(
    sdbusplus::asio::connection& bus, const std::string& path,
    const std::vector<std::string>& interfaces = {})
{
    auto h = make_awaitable_handler<Dict>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           Dict dict) mutable {
                promise.setValues(ec, std::move(dict));
            },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetObject", path, interfaces);
    });
    co_return co_await h();
}
template <typename Dict>
inline AwaitableResult<Dict> getSubTreePaths(
    sdbusplus::asio::connection& bus, const std::string& path, int depth,
    const std::vector<std::string>& interfaces = {})
{
    auto h = make_awaitable_handler<Dict>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           Dict dict) mutable {
                promise.setValues(ec, std::move(dict));
            },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths", path, depth,
            interfaces);
    });
    co_return co_await h();
}
template <typename Dict>
inline AwaitableResult<Dict> getAssociatedSubTree(
    sdbusplus::asio::connection& bus,
    const sdbusplus::message::object_path& associatedPath,
    const sdbusplus::message::object_path& path, int depth,
    const std::vector<std::string>& interfaces = {})
{
    auto h = make_awaitable_handler<Dict>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           Dict dict) mutable {
                promise.setValues(ec, std::move(dict));
            },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetAssociatedSubTree",
            associatedPath, path, depth, interfaces);
    });
    co_return co_await h();
}

template <typename Dict>
inline AwaitableResult<Dict> getAssociatedSubTreePaths(
    sdbusplus::asio::connection& bus,
    const sdbusplus::message::object_path& associatedPath,
    const sdbusplus::message::object_path& path, int32_t depth,
    const std::vector<std::string>& interfaces = {})
{
    auto h = make_awaitable_handler<Dict>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           Dict dict) mutable {
                promise.setValues(ec, std::move(dict));
            },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetAssociatedSubTreePaths",
            associatedPath, path, depth, interfaces);
    });
    co_return co_await h();
}

template <typename Dict>
inline AwaitableResult<Dict> getAssociatedSubTreeById(
    sdbusplus::asio::connection& bus, const std::string& id,
    const std::string& path,
    std::span<const std::string_view> subtreeInterfaces,
    std::string_view association,
    const std::vector<std::string>& endpointInterfaces = {})
{
    auto h = make_awaitable_handler<Dict>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           Dict dict) mutable {
                promise.setValues(ec, std::move(dict));
            },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetAssociatedSubTreeById", id,
            path, subtreeInterfaces, association, endpointInterfaces);
    });
    co_return co_await h();
}

template <typename Dict>
inline AwaitableResult<Dict> getAssociatedSubTreePathsById(
    sdbusplus::asio::connection& bus, const std::string& id,
    const std::string& path,
    std::span<const std::string_view> subtreeInterfaces,
    std::string_view association,
    const std::vector<std::string>& endpointInterfaces)
{
    auto h = make_awaitable_handler<Dict>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           Dict dict) mutable {
                promise.setValues(ec, std::move(dict));
            },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetAssociatedSubTreePathsById",
            id, path, subtreeInterfaces, association, endpointInterfaces);
    });
    co_return co_await h();
}

template <typename Dict>
inline AwaitableResult<Dict> getDbusObject(
    sdbusplus::asio::connection& bus, const std::string& path,
    const std::vector<std::string>& interfaces = {})
{
    auto h = make_awaitable_handler<Dict>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           Dict dict) mutable {
                promise.setValues(ec, std::move(dict));
            },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetObject", path, interfaces);
    });
    co_return co_await h();
}

template <typename Dict>
inline AwaitableResult<Dict> getAssociationEndPoints(
    sdbusplus::asio::connection& bus, const std::string& path)
{
    co_return co_await getProperty<Dict>(
        bus, "xyz.openbmc_project.ObjectMapper", path,
        "xyz.openbmc_project.Association", "endpoints");
}

template <typename Dict>
inline AwaitableResult<Dict> getManagedObjects(
    sdbusplus::asio::connection& bus, const std::string& service,
    const sdbusplus::message::object_path& path)
{
    auto h = make_awaitable_handler<Dict>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           Dict dict) mutable {
                promise.setValues(ec, std::move(dict));
            },
            service, path, "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects");
    });
    co_return co_await h();
}
template <typename Dict>
inline AwaitableResult<Dict> getAncestors(
    sdbusplus::asio::connection& bus, const std::string& path,
    const std::vector<std::string>& interfaces = {})
{
    auto h = make_awaitable_handler<Dict>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           Dict dict) mutable {
                promise.setValues(ec, std::move(dict));
            },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetAncestors", path,
            interfaces);
    });
    co_return co_await h();
}

inline AwaitableResult<std::string> introspect(
    sdbusplus::asio::connection& bus, const std::string& service,
    const sdbusplus::message::object_path& path)
{
    auto h = make_awaitable_handler<std::string>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           std::string str) mutable {
                promise.setValues(ec, std::move(str));
            },
            service, path, "org.freedesktop.DBus.Introspectable", "Introspect");
    });
    co_return co_await h();
}
}