#pragma once

#include <queue>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "SHA.h"

struct ThreadData
{
	std::unordered_map<std::string, int> path_hitcount;
	std::unordered_map<std::string, int> user_agent_hitcount;
};

struct QueueData
{
	std::string path;
	std::string user_agent;
};

class WorkingWithQueue
{
private:
	std::queue<QueueData> queue_;
	std::mutex queue_mutex_;
	std::condition_variable queue_bell_;

	SHA sha_;

public:
	void AddQueue(const std::string &path, const std::string &user_agent)
	{
		std::lock_guard<std::mutex> lg(queue_mutex_);

		queue_.push({path, user_agent});

		queue_bell_.notify_one();
	}

	void HashAndPrint(ThreadData &t_data)
	{
		while (true)
		{
			std::unique_lock<std::mutex> ul(queue_mutex_);
			queue_bell_.wait(ul, [=]()
			{
				return !queue_.empty();
			});

			auto rd = queue_.front();
			queue_.pop();

			std::string path(rd.path);
			std::string path_sha(sha_.GetHash(rd.path));
			auto path_hitcount_int = t_data.path_hitcount[rd.path];
			std::string path_hitcoin(std::to_string(path_hitcount_int));
			t_data.path_hitcount[rd.path] += 1;

			std::string user_agent(rd.user_agent);
			std::string user_agent_sha(sha_.GetHash(rd.user_agent));
			auto user_agent_hitcoin_int = t_data.path_hitcount[rd.user_agent];
			std::string user_agent_hitcoin(std::to_string(user_agent_hitcoin_int));
			t_data.path_hitcount[rd.user_agent] += 1;

			std::cout << std::this_thread::get_id() << " "
			          << path << " " << path_sha << " " << path_hitcoin << " "
			          << user_agent << " " << user_agent_sha << " " << user_agent_hitcoin << std::endl;

			queue_bell_.notify_one();
		}
	}
};
