#include "LiteServer.h"


LiteServer::LiteServer(size_t event_size, size_t buffer_read_capacity)
: EPOLL_SIZE_(event_size)
, BUFFER_READ_CAPACITY_(buffer_read_capacity)
{
	sock_fd_ = -1;
	ctx_ = nullptr;

	epoll_fd_ = -1;
	epoll_events_ = new epoll_event[EPOLL_SIZE_];
	epoll_events_count_ = 0;

	buffer_read_tmp_size_ = 0;
	buffer_read_tmp_ = new char[BUFFER_READ_CAPACITY_];
	bzero(buffer_read_tmp_, BUFFER_READ_CAPACITY_);

	callback_ = nullptr;
}

LiteServer::~LiteServer()
{
	close(sock_fd_);
	SSL_CTX_free(ctx_);

	close(epoll_fd_);

	delete epoll_events_;
	delete buffer_read_tmp_;
}

bool LiteServer::Init(const char* server_ip, int port, const char* server_cert, const char* server_key)
{
	signal(SIGPIPE, SIG_IGN);
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	//std::cout << OPENSSL_VERSION_TEXT << std::endl;


	ctx_ = SSL_CTX_new(TLS_server_method());
	if (!ctx_)
	{
		std::cerr << "Unable to create SSL context" << std::endl;
		ERR_print_errors_fp(stderr);
		return false;
	}

	SSL_CTX_set_cipher_list(ctx_, "ALL:eNULL");

	// Set the key and cert
	if (SSL_CTX_use_certificate_file(ctx_, server_cert, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx_, server_key, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		return false;
	}

	// verify private key
	if (!SSL_CTX_check_private_key(ctx_))
	{
		std::cerr << "Private key does not match the public certificate" << std::endl;
		return false;
	}

	// create socket
	struct sockaddr_in addr{};

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(server_ip);

	sock_fd_ = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd_ < 0)
	{
		std::cerr << "Unable to create socket" << std::endl;
		return false;
	}

	if (fcntl(sock_fd_, F_SETFL, fcntl(sock_fd_, F_GETFL, 0) | O_NONBLOCK) != 0)
	{
		std::cerr << "Unable to nonblock" << std::endl;
		return false;
	}

	if (bind(sock_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		std::cerr << "Unable to bind" << std::endl;
		return false;
	}

	if (listen(sock_fd_, 1) < 0)
	{
		std::cerr << "Unable to listen" << std::endl;
		return false;
	}

	//epoll
	epoll_fd_ = epoll_create((int)EPOLL_SIZE_);
	if (epoll_fd_ < 0)
	{
		std::cerr << "Unable to epoll_create" << std::endl;
		return false;
	}


	struct epoll_event ev;
	ev.data.fd = sock_fd_;
	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLOUT;
	if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, sock_fd_, &ev) != 0)
	{
		std::cerr << "Unable to epoll_ctl" << std::endl;
		return false;
	}

	return true;
}

bool LiteServer::Process()
{
	struct sockaddr_in addr{};
	unsigned int addr_len = sizeof(addr);

	while (true)
	{
		epoll_events_count_ = epoll_wait(epoll_fd_, epoll_events_, (int)EPOLL_SIZE_, 10000);
		if (epoll_events_count_ < 0)
		{
			std::cerr << "epoll_wait failed!" << std::endl;
			return false;
		}

		for (int i = 0; i < epoll_events_count_ ; i++)
		{
			if (epoll_events_[i].data.fd == sock_fd_)
			{
				ClientInfo client;
				client.fd = accept(sock_fd_, (struct sockaddr *)&addr, &addr_len);
				if (client.fd < 0)
					continue;

				client.ssl = SSL_new(ctx_);
				SSL_set_fd(client.ssl, client.fd);

				// setup nonblocking socket
				if (fcntl(sock_fd_, F_SETFL, fcntl(sock_fd_, F_GETFL, 0) | O_NONBLOCK) != 0)
				{
					std::cerr << "error nonblock" << std::endl;
					return false;
				}

				struct epoll_event ev;
				ev.data.fd = client.fd;
				ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLOUT;
				if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client.fd, &ev) != 0)
				{
					std::cerr << "error epoll_ctl" << std::endl;
					return false;
				}

				while (true)
				{
					auto err = SSL_accept(client.ssl);

					const int code = SSL_get_error(client.ssl, err);
					if ((code != SSL_ERROR_WANT_READ) && (code != SSL_ERROR_WANT_WRITE))
						break;
				}

				clients_[client.fd] = client;
				//clients_.push_back(client);
			}
			else
			{
				if (clients_.find(epoll_events_[i].data.fd) == clients_.end())
				{
					std::cerr << "not found fd:" << epoll_events_[i].data.fd << std::endl;
					break;
				}

				auto client = clients_[epoll_events_[i].data.fd];

				SSLRead(client);
				if (ParseRequest(client))
				{
					SSLWrite(client);
					if (callback_)
						callback_(client.request_data);
				}

				if (epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, client.fd, nullptr) != 0)
				{
					std::cerr << "error epoll_ctl" << std::endl;
					return false;
				}
				SSL_shutdown(client.ssl);
				SSL_free(client.ssl);
				close(client.fd);
				clients_.erase(clients_.find(client.fd));
			}
		}
	}

	return true;
}

void LiteServer::SSLRead(ClientInfo &ci)
{
	buffer_read_tmp_size_ = 0;
	while (buffer_read_tmp_size_ < BUFFER_READ_CAPACITY_ - 1)
	{
		auto err = SSL_read(ci.ssl, &buffer_read_tmp_[buffer_read_tmp_size_],
							int(BUFFER_READ_CAPACITY_ - buffer_read_tmp_size_ - 1));
		if (err > 0)
		{
			ci.request.append(&buffer_read_tmp_[buffer_read_tmp_size_], err);

			if (ci.request.find("\r\n\r\n") != std::string::npos || ci.request.find("\n\n") != std::string::npos)
				break;

			continue;
		}

		const int code = SSL_get_error(ci.ssl, err);
		if ((code != SSL_ERROR_WANT_READ) && (code != SSL_ERROR_WANT_WRITE))
		{
			break;
		}
	}
}

void LiteServer::SSLWrite(ClientInfo &ci)
{
	auto pos = 0;
	while (pos < RESPONSE_.length())
	{
		auto err = SSL_write(ci.ssl, &RESPONSE_[pos], int(RESPONSE_.length() - pos));
		if (err > 0)
		{
			pos += err;
			continue;
		}

		const int code = SSL_get_error(ci.ssl, err);
		if ((code != SSL_ERROR_WANT_READ) && (code != SSL_ERROR_WANT_WRITE))
			break;
	}
}

bool LiteServer::ParseRequest(ClientInfo &ci)
{
	/*
	GET path HTTP/1.1
	Host: host
	User-Agent: user_agent
	*/

	std::string method;
	auto pos1 = ci.request.find(' ');
	if (pos1 != std::string::npos)
	{
		method = ci.request.substr(0, pos1);
		if (method == "GET")
		{
			pos1 += 1;
			auto pos2 = ci.request.find(" HTTP/1.1");
			if (pos2 != std::string::npos)
				ci.request_data.path = ci.request.substr(pos1, pos2 - pos1);

			auto pos3 = ci.request.find("User-Agent: ");
			if (pos3 != std::string::npos)
			{
				pos3 += 12;
				std::string tmp = ci.request.substr(pos3, ci.request.length());
				auto pos4 = tmp.find("\r\n");
				if (pos4 == std::string::npos)
					pos4 = tmp.find('\n');
				if (pos4 != std::string::npos)
				{
					ci.request_data.user_agent = tmp.substr(0, pos4);
				}
				return true;
			}
		}
	}

	return false;
}
