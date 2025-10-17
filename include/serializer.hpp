#pragma once

#include "logger.hpp"

#include <nlohmann/json.hpp>

#include <format>
#include <fstream>
#include <ranges>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
namespace NSNAME
{
class JsonSerializer
{
  public:
    JsonSerializer(std::string path, nlohmann::json js = nlohmann::json()) :
        serPath(path), jsonData(std::move(js))
    {}
    inline auto stringSplitter()
    {
        return std::views::split('/') | std::views::transform([](auto&& sub) {
                   return std::string(sub.begin(), sub.end());
               });
    }

    nlohmann::json makeJson(const std::string& key, const auto& value)
    {
        auto keys = key | stringSplitter();
        std::vector v(keys.begin(), keys.end());
        auto rv = v | std::views::reverse;
        nlohmann::json init;
        init[rv.front()] = value;
        auto newJson = std::reduce(rv.begin() + 1, rv.end(), init,
                                   [](auto sofar, auto currentKey) {
                                       nlohmann::json j;
                                       j[currentKey] = sofar;
                                       return j;
                                   });
        return newJson;
    }
    std::optional<nlohmann::json> getLeafNode(const std::string_view keyPath)
    {
        auto keys = keyPath | stringSplitter();
        nlohmann::json current = jsonData;
        for (auto key : keys)
        {
            if (!current.contains(key))
            {
                return std::nullopt;
            }
            current = current[key];
        }
        return current;
    }
    template <typename T>
    void serialize(const std::string& key, const T& value)
    {
        jsonData.merge_patch(makeJson(key, value));
    }
    template <typename T>
    void deserialize(std::string key, T& value)
    {
        auto leaf = getLeafNode(key);
        if (leaf)
        {
            value = *leaf;
        }
    }
    void erase(std::string key)
    {
        if (jsonData.contains(key))
        {
            jsonData.erase(key);
        }
    }
    bool store()
    {
        std::filesystem::path dir =
            std::filesystem::path(serPath).parent_path();

        // Check if the directory exists, and create it if it does not
        if (!dir.string().empty() && !std::filesystem::exists(dir))
        {
            std::error_code ec;
            if (!std::filesystem::create_directories(dir, ec))
            {
                LOG_ERROR("Unable to create directory {}", dir.string());
                return false;
            }
        }
        std::ofstream file(serPath.data());
        if (file.is_open())
        {
            LOG_INFO("Storing data {} to  {}", jsonData.dump(4), serPath);
            file << jsonData.dump(4); // Pretty print with 4 spaces
            file.close();
            std::error_code ec;
            return true;
        }

        LOG_ERROR("Unable to open file for writing {}", serPath);
        return false;
    }
    void load()
    {
        std::ifstream file(serPath.data());

        if (file.is_open())
        {
            file >> jsonData;
            file.close();
        }
        else
        {
            LOG_ERROR("Unable to open file for reading {}", serPath);
        }
    }

  private:
    const std::string serPath;
    nlohmann::json jsonData;
};
}