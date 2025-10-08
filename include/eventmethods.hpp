#pragma once
#include "tcp_server.hpp"

#include <filesystem>
#include <fstream>
namespace NSNAME
{
static constexpr auto DONE = "Done";
static constexpr auto HEDER_DELIM = "\r\n\r\n";
static constexpr auto BUFFER_SIZE = 8192;
using Streamer = TimedStreamer<ssl::stream<tcp::socket>>;
namespace fs = std::filesystem;
static constexpr auto timeoutneeded = false;
inline u_int64_t epocNow()
{
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
inline std::string currentTime()
{
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) %
                  1000;
    auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                      now.time_since_epoch()) %
                  1000;

    std::tm tm = *std::localtime(&now_time_t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%H:%M:%S") << '.' << std::setw(3)
        << std::setfill('0') << now_ms.count() << '.' << std::setw(3)
        << std::setfill('0') << now_us.count();
    return oss.str();
}
inline std::string makeEvent(const std::string& id, const std::string& data,
                             const std::string& delim = HEDER_DELIM)
{
    return std::format("{}:{}{}", id, data, delim);
}
inline std::string makeEvent(const std::string& data)
{
    return std::format("{}{}", data, HEDER_DELIM);
}
inline std::pair<std::string, std::string> parseEvent(const std::string& event)
{
    auto pos = event.find(':');
    if (pos == std::string::npos)
    {
        return {event, ""};
    }
    return {event.substr(0, pos), event.substr(pos + 1)};
}
inline AwaitableResult<size_t> readData(Streamer streamer,
                                        net::mutable_buffer buffer)
{
    auto [ec, size] = co_await streamer.read(buffer, timeoutneeded);
    if (ec)
    {
        LOG_DEBUG("Error reading: {}", ec.message());
        co_return std::make_pair(ec, size);
    }
    co_return std::make_pair(ec, size);
}
inline AwaitableResult<size_t> sendData(Streamer streamer,
                                        net::const_buffer buffer)
{
    auto [ec, size] = co_await streamer.write(buffer, timeoutneeded);
    if (ec)
    {
        LOG_ERROR("Error writing: {}", ec.message());
        co_return std::make_pair(ec, size);
    }
    co_return std::make_pair(ec, size);
}
inline AwaitableResult<std::string> readHeader(Streamer streamer)
{
    auto [ec, data] = co_await streamer.readUntil(HEDER_DELIM, timeoutneeded);
    if (ec)
    {
        LOG_INFO("Error reading: {}", ec.message());
        co_return std::make_pair(ec, data);
    }
    auto delimLength = std::string_view(HEDER_DELIM).length();
    data.erase(data.length() - delimLength, delimLength);
    LOG_DEBUG("{} Recieved Header: {}", currentTime(), data);
    co_return std::make_pair(ec, data);
}
inline AwaitableResult<size_t> sendHeader(Streamer streamer,
                                          const std::string& data)
{
    std::string header = std::format("{}{}", data, HEDER_DELIM);
    LOG_DEBUG("{} Sending Header: {}", currentTime(), header);
    auto [ec,
          size] = co_await streamer.write(net::buffer(header), timeoutneeded);
    if (ec)
    {
        LOG_ERROR("Failed to write to stream: {}", ec.message());
    }
    co_return std::make_pair(ec, size);
}
net::awaitable<boost::system::error_code> sendDone(Streamer streamer)
{
    auto [ec, size] = co_await sendHeader(streamer, DONE);
    co_return ec;
}
AwaitableResult<std::string> readDone(Streamer streamer)
{
    auto [ec, data] = co_await streamer.readUntil(HEDER_DELIM, true);
    if (ec)
    {
        LOG_INFO("Error reading Done: {}", ec.message());
        co_return std::make_pair(ec, data);
    }
    auto delimLength = std::string_view(HEDER_DELIM).length();
    data.erase(data.length() - delimLength, delimLength);
    LOG_INFO("{} Recieved Header: {}", currentTime(), data);
    co_return std::make_pair(ec, data);
}
}