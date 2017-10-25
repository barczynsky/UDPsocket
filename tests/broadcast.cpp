#include <chrono>
#include <string>
#include <thread>
using namespace std::literals;
#include "UDPsocket.h"


static constexpr uint16_t port = 2020;


void test_broadcast()
{

	UDPsocket ss;
	ss.open();
	ss.bind(port);

	UDPsocket cs;
	cs.open();
	cs.broadcast(true);

	auto t1 = std::thread([&ss, &cs]
	{
		std::this_thread::sleep_for(1s);
		while (true)
		{
			UDPsocket::IPv4 ipaddr;
			std::string data;
			if (ss.recv(data, ipaddr) < 0)
			{
				fprintf(stderr, "recv(): failed\n");
			}
			else
			{
				fprintf(stderr, "%s  '%s'\n", ipaddr.to_string().c_str(), data.c_str());
				if (data.compare(0, 8, "MESSAGE?"s) == 0)
				{
					ipaddr.port = port;
					if (cs.send("MESSAGE!"s, ipaddr) < 0)
					{
						fprintf(stderr, "send(): failed\n");
					}
				}
			}
		}
	});

	auto t2 = std::thread([&cs]
	{
		while (true)
		{
			if (cs.send("MESSAGE?"s, UDPsocket::IPv4::Broadcast(port)) < 0)
			{
				fprintf(stderr, "send(): failed\n");
			}
			std::this_thread::sleep_for(1s);
		}
	});

	t1.join();
	t2.join();
}


int main()
{
	test_broadcast();
	return 0;
}
