#include <getopt.h>

#include "LiteServer.h"
#include "WorkingWithQueue.h"

struct Thread
{
	std::thread th;
	ThreadData th_data;
};

[[noreturn]] void PrintfHelp()
{
	std::cout << "This is help:" << std::endl;
	std::cout << std::endl;
	std::cout << "Options:" << std::endl;
	std::cout << "\t-h, --help\thelp output" << std::endl;
	std::cout << std::endl;
	std::cout << "Options + argument:" << std::endl;
	std::cout << "\t-i, --ip\tspecify the server ip (default localhost)" << std::endl;
	std::cout << "\t-p, --port\tspecify the server port (default 4433)" << std::endl;
	std::cout << "\t-c, --cert\tspecify the certificate filename (default ../cert.pem)" << std::endl;
	std::cout << "\t-k, --key\tspecify the key filename (default ../key.pem)" << std::endl;
	std::cout << "\t-n, --numb\tspecify the number of threads working with the queue (default 5)" << std::endl;
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	std::string server_ip = "127.0.0.1";
	int port = 4433;
	std::string cert_file = "../cert.pem";
	std::string key_file = "../key.pem";
	int thread_count = 5;

	//arguments
	const char* short_options = "i:p:c:k:n:h";
	const struct option long_options[] = {
			{"help", 	no_argument,		nullptr, 'h'},
			{"ip", 		required_argument,	nullptr, 'i'},
			{"port", 	required_argument,	nullptr, 'p'},
			{"cert", 	required_argument,	nullptr, 'c'},
			{"key", 	required_argument,	nullptr, 'k'},
			{"numb", 	required_argument,	nullptr, 'n'},
			{nullptr,0,nullptr,0}
	};
	int rez, option_index;

	while ((rez = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
	{
		switch (rez)
		{
		case 'h':
			PrintfHelp();
		case 'i':
			server_ip = optarg;
			break;
		case 'p':
			port = (int)strtol(optarg, nullptr, 10);
			break;
		case 'c':
			cert_file = optarg;
			break;
		case 'k':
			key_file = optarg;
			break;
		case 'n':
			thread_count = (int)strtol(optarg, nullptr, 10);
			break;
		default:
			break;
		}
	}


	WorkingWithQueue ww_queue;
	LiteServer server;


	if (!server.Init(server_ip.c_str(), port, cert_file.c_str(), key_file.c_str()))
		exit(EXIT_FAILURE);
	std::cout << "server initialized:" << std::endl;
	std::cout << "\tserver_ip: " << server_ip << std::endl;
	std::cout << "\tport:      " << port << std::endl;
	std::cout << "\tcert_file: " << cert_file << std::endl;
	std::cout << "\tkey_file:  " << key_file << std::endl;

	server.SetCallback([&ww_queue](const RequestData &request)
	{
		ww_queue.AddQueue(request.path, request.user_agent);
	});


	std::vector<Thread> threads(thread_count);
	for (auto &thread : threads)
		thread.th = std::thread(&WorkingWithQueue::HashAndPrint, std::ref(ww_queue), std::ref(thread.th_data));
	std::cout << threads.size() << " threads created" << std::endl;

	std::cout << "server is running" << std::endl;
	if (!server.Process())
		exit(EXIT_FAILURE);

	for (auto &thread : threads)
		thread.th.join();

	exit(EXIT_SUCCESS);
}
