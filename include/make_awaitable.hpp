#pragma once
#include "beastdefs.hpp"
namespace NSNAME
{
template <typename... Types>
using PrependEC = std::tuple<boost::system::error_code, Types...>;
template <typename... RetTypes>
using ReturnTuple = std::conditional_t<
    std::is_same_v<boost::system::error_code,
                   std::tuple_element_t<0, std::tuple<RetTypes...>>>,
    std::tuple<RetTypes...>, PrependEC<RetTypes...>>;

template <typename... Types>
using AwaitableResult = net::awaitable<ReturnTuple<Types...>>;
template <typename Handler, typename... Types>
struct PromiseType
{
    mutable Handler promise;
    void setValues(Types... values) const
    {
        promise(ReturnTuple<Types...>{std::move(values)...});
    }
};

template <typename... Ret, typename HanlderFunc>
auto make_awaitable_handler(HanlderFunc&& h)
{
    return [h = std::move(h)]() -> AwaitableResult<Ret...> {
        co_return co_await net::async_initiate<
            const net::use_awaitable_t<>,
            ReturnTuple<Ret...>(ReturnTuple<Ret...>)>(
            [h = std::move(h)](auto handler) {
                if constexpr (std::is_same_v<
                                  boost::system::error_code,
                                  std::tuple_element_t<0, std::tuple<Ret...>>>)
                {
                    PromiseType<decltype(handler), Ret...> promise{
                        std::move(handler)};
                    h(std::move(promise));
                }
                else
                {
                    PromiseType<decltype(handler), boost::system::error_code,
                                Ret...>
                        promise{std::move(handler)};
                    h(std::move(promise));
                }
            },
            net::use_awaitable);
    };
}
}