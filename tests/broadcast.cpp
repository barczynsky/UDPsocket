#include <chrono>
#include <string>
#include <thread>
using namespace std::literals;

#include "UDPsocket.h"


static constexpr uint16_t PortNo = 2020;
static constexpr uint8_t IterCount = 20;
static constexpr auto IterDuration = 1s;


void test_broadcast()
{
	UDPsocket ss;
	ss.open();
	ss.bind(PortNo);

	UDPsocket cs;
	cs.open();
	cs.broadcast(true);

	auto t1 = std::thread([&ss, &cs]
	{
		std::this_thread::sleep_for(IterDuration * 1.25);
		for (uint16_t i = 0; i < 2 * IterCount; ++i)
		{
			UDPsocket::IPv4 ipaddr;
			std::string data;
			if (ss.recv(data, ipaddr) < 0)
			{
				fprintf(stderr, "recv(): failed\n");
			}
			else
			{
				if (!data.empty())
				{
					fprintf(stderr, "%s  '%s'\n", ipaddr.to_string().c_str(), data.c_str());
					if (data.compare(0, 8, "MESSAGE?"s) == 0)
					{
						ipaddr.port = PortNo;
						if ((i & 0x2 ? cs : ss).send("MESSAGE!"s, ipaddr) < 0)
						{
							fprintf(stderr, "send(): failed (REP)\n");
						}
					}
				}
			}
		}
		ss.close();
	});

	auto t2 = std::thread([&cs]
	{
		for (uint8_t i = 0; i < IterCount; ++i)
		{
			if (cs.send("MESSAGE?"s, UDPsocket::IPv4::Broadcast(PortNo)) < 0)
			{
				fprintf(stderr, "send(): failed (REQ)\n");
			}
			std::this_thread::sleep_for(IterDuration);
		}
		cs.close();
	});

	t1.join();
	t2.join();
}


int main()
{
	test_broadcast();
	return 0;
}
