#pragma once
#include <iostream>
#include <cstdio>
#include <unistd.h>
#include <cstring>
#include <string_view>
#include <utility>
#include <vector>
#include <functional>
#include <csignal>
#include <unordered_map>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct RequestData
{
	std::string path;
	std::string user_agent;
};

typedef void TypeLiteServerCallbackFunction(const RequestData &request);

class LiteServer
{
public:
	struct ClientInfo
	{
		int fd = -1;
		SSL *ssl = nullptr;
		std::string request;
		RequestData request_data;
	};

	explicit LiteServer(size_t event_size = 1000, size_t buffer_read_capacity = 4096);
	~LiteServer();

	bool Init(const char* server_ip, int port, const char* server_cert, const char* server_key);
	bool Process();

	void SetCallback(std::function<void(const RequestData &request)> cb)
	{
		callback_ = std::move(cb);
	}

private:
	const size_t EPOLL_SIZE_;
	const size_t BUFFER_READ_CAPACITY_;

	const std::string RESPONSE_ = "HTTP/1.1 200 OK"
								  "\r\n"
								  "Content-Length: 6"
								  "\r\n"
								  "\r\n"
								  "queued";

	int sock_fd_;

	int epoll_fd_;
	int epoll_events_count_;
	epoll_event *epoll_events_;

	SSL_CTX *ctx_;

	char *buffer_read_tmp_;
	size_t buffer_read_tmp_size_;

	std::unordered_map<int, ClientInfo> clients_;

	std::function<void(const RequestData &request)> callback_;

	void SSLRead(ClientInfo &ci);
	void SSLWrite(ClientInfo &ci);
	bool ParseRequest(ClientInfo &ci);
};
