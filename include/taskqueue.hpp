#pragma once
#include "tcp_client.hpp"

#include <deque>
namespace NSNAME
{
using Streamer = TimedStreamer<ssl::stream<tcp::socket>>;
class TaskQueue
{
    using Task =
        std::function<net::awaitable<boost::system::error_code>(Streamer)>;
    struct Client
    {
        TcpClient client;
        bool available = true;
        Client(net::any_io_executor ioContext, net::ssl::context& sslContext) :
            client(ioContext, sslContext)
        {}
        ~Client()
        {
            // client.close();
        }
        bool isAvailable() const
        {
            return available;
        }
        TcpClient& acquire()
        {
            available = false;
            return client;
        }
        bool operator==(TcpClient& other) const
        {
            return &client == &other;
        }
        void release()
        {
            available = true;
        }
        bool isOpen() const
        {
            return client.isOpen();
        }
    };
    struct NetworkTask
    {
        Task task;
        std::reference_wrapper<Client> client;
        bool empty() const
        {
            return !task;
        }
    };

  public:
    struct EndPoint
    {
        std::string url;
        std::string port;
        operator bool() const
        {
            return !url.empty();
        }
    };

  public:
    TaskQueue(net::any_io_executor ioContext, net::ssl::context& sslContext,
              int maxConnections = 1) :
        sslContext(sslContext), ioContext(ioContext), maxClients(maxConnections)
    {}
    TaskQueue(net::any_io_executor ioContext, net::ssl::context& sslContext,
              const std::string& url, const std::string& port,
              int maxConnections = 1) :
        endPoint{url, port}, sslContext(sslContext), ioContext(ioContext),
        maxClients(maxConnections)
    {}
    void setEndPoint(const std::string& url, const std::string& port)
    {
        endPoint = EndPoint{url, port};

        net::co_spawn(ioContext,
                      std::bind_front(&TaskQueue::processTasks, this),
                      net::detached);
    }
    auto getEndPoint() const
    {
        return endPoint;
    }
    void addTask(Task messageHandler, bool front = false)
    {
        bool processNow = taskHandlers.size() < maxClients;
        if (front)
        {
            taskHandlers.emplace_front(std::move(messageHandler));
        }
        else
        {
            taskHandlers.emplace_back(std::move(messageHandler));
        }
        if (processNow)
        {
            net::co_spawn(ioContext,
                          std::bind_front(&TaskQueue::processTasks, this),
                          net::detached);
        }
    }

    net::awaitable<void> handleTask(NetworkTask netTask)
    {
        auto steamer = netTask.client.get().acquire().streamer();
        auto ec = co_await netTask.task(steamer);
        if (!ec)
        {
            netTask.client.get().release();
            // if more tasks are available, we can continue
            if (!taskHandlers.empty())
            {
                co_spawn(
                    ioContext,
                    std::bind_front(&TaskQueue::handleTask, this,
                                    NetworkTask{takeTask(), netTask.client}),
                    net::detached);
            }
            co_return;
        }
        // the connection is closed, we need to
        // remove the client from the list
        removeClient(netTask.client);
        // start new task if available with new client
        net::co_spawn(ioContext,
                      std::bind_front(&TaskQueue::processTasks, this),
                      net::detached);
        co_return;
    }
    void removeClient(std::reference_wrapper<Client> client)
    {
        clients.erase(std::remove_if(clients.begin(), clients.end(),
                                     [&client](auto& c) {
                                         return c.get() == &client.get();
                                     }),
                      clients.end());
        // remove all closed clients
        clients.erase(std::remove_if(clients.begin(), clients.end(),
                                     [](auto& c) { return !c->isOpen(); }),
                      clients.end());
    }
    net::awaitable<void> processTasks()
    {
        if (!endPoint)
        {
            LOG_INFO("EndPoint is not set, cannot process tasks");
            co_return;
        }
        if (!taskHandlers.empty())
        {
            auto taskEntry = co_await getTask();
            if (!taskEntry)
            {
                // if connection is not available, retry for tasks if any
                // after 5 seconds
                co_await waitFor(5s);
                net::co_spawn(ioContext,
                              std::bind_front(&TaskQueue::processTasks, this),
                              net::detached);
                co_return;
            }
            co_spawn(ioContext,
                     std::bind_front(&TaskQueue::handleTask, this,
                                     std::move(*taskEntry)),
                     net::detached);
        }

        co_return;
    }
    Task takeTask()
    {
        auto message = std::move(taskHandlers.front());
        taskHandlers.pop_front();
        return message;
    }
    net::awaitable<std::optional<NetworkTask>> getTask()
    {
        auto client = co_await getAvailableClient();
        if (client)
        {
            if (taskHandlers.empty())
            {
                client.value().get().release();
                co_return std::nullopt;
            }
            co_return NetworkTask{takeTask(), *client};
        }
        co_return std::nullopt;
    }

  private:
    net::awaitable<void> waitFor(std::chrono::seconds seconds)
    {
        net::steady_timer timer(ioContext);
        timer.expires_after(seconds);
        co_await timer.async_wait(net::use_awaitable);
        co_await net::post(co_await net::this_coro::executor,
                           net::use_awaitable);
        co_return;
    }
    std::optional<std::reference_wrapper<Client>> getFreeClient()
    {
        for (auto& client : clients)
        {
            if (client->isAvailable())
            {
                client->acquire();
                return std::ref(*client);
            }
        }
        return std::nullopt;
    }
    net::awaitable<std::optional<std::reference_wrapper<Client>>>
        getAvailableClient()
    {
        auto freeclient = getFreeClient();
        if (freeclient)
        {
            co_return freeclient;
        }
        if (clients.size() < maxClients)
        {
            auto client = std::make_unique<Client>(ioContext, sslContext);
            auto ec = co_await tryConnect(client->acquire());
            if (!ec)
            {
                auto clientToRet = std::ref(*client);
                clients.emplace_back(std::move(client));
                co_return clientToRet;
            }
        }
        co_return std::nullopt;
    }
    net::awaitable<boost::system::error_code> tryConnect(TcpClient& client)
    {
        net::steady_timer timer(ioContext);

        int i = 0;
        while (i < maxRetryCount)
        {
            auto ec = co_await client.connect(endPoint.url, endPoint.port);
            if (!ec)
            {
                co_return ec;
            }
            LOG_WARNING("Failed to connect to {}:{}. Retrying {}/{}",
                        endPoint.url, endPoint.port, i + 1, maxRetryCount);
            timer.expires_after(5s);
            co_await timer.async_wait(net::use_awaitable);
            i++;
        }

        co_return boost::system::errc::make_error_code(
            boost::system::errc::connection_refused);
    }

    std::deque<Task> taskHandlers;
    std::vector<std::unique_ptr<Client>> clients;
    EndPoint endPoint;
    net::ssl::context& sslContext;
    net::any_io_executor ioContext;
    int maxRetryCount{3};
    size_t maxClients{1};
    bool started{false};
};
}