#pragma once
#include "name_space.hpp"

#include <algorithm>
#include <ranges>
#include <string>
#include <vector>
namespace NSNAME
{
inline std::string toString(std::string_view vw)
{
    return std::string(vw.data(), vw.length());
}
inline auto stringSplitter(char c, int skip = 0)
{
    return std::views::split(c) | std::views::drop(skip) |
           std::views::transform([](auto&& sub) {
               return std::string_view(sub.begin(), sub.end());
           });
}
inline auto split(const std::string_view& input, char c, int skip = 0)
{
    auto vw = input | stringSplitter(c, skip);
    return std::vector(vw.begin(), vw.end());
}
inline auto join(const auto& input, char c)
{
    std::string result;
    for (auto v : input)
    {
        result += c + toString(v);
    }
    return result;
}
inline void replaced(const std::string& input, char c, char r, auto outiter)
{
    std::transform(begin(input), end(input), outiter,
                   [c, r](char ch) { return ch == c ? r : ch; });
}

} // namespace NSNAME
