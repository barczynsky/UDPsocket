#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifndef INPORT_ANY
#define INPORT_ANY 0
#endif

#include <cstring>
#include <array>
#include <string>
using namespace std::literals;


class UDPsocket
{
public:
	typedef struct sockaddr_in sockaddr_in_t;
	typedef struct sockaddr sockaddr_t;
	struct IPv4;
	enum class Status;

private:
	int sock{ -1 };
	sockaddr_in_t self_addr{};
	socklen_t self_addr_len = sizeof(self_addr);

public:
	UDPsocket()
	{
#ifdef _WIN32
		WSAInit();
#endif
		std::memset(&self_addr, 0, self_addr_len);
	}

	~UDPsocket()
	{
		this->close();
	}

public:
	int open()
	{
		this->close();
		sock = ::socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock <= 0) {
			return (int)Status::SocketError;
		}
		return (int)Status::OK;
	}

	int bind(uint16_t portno)
	{
		std::memset(&self_addr, 0, self_addr_len);
		self_addr.sin_family = AF_INET;
		self_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		self_addr.sin_port = htons(portno);
		int opt = 1;
		int ret = ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
		if (ret < 0) {
			return (int)Status::SetSockOptError;
		}
		ret = ::bind(sock, (sockaddr_t*)&self_addr, self_addr_len);
		if (ret < 0) {
			return (int)Status::BindError;
		}
		return (int)Status::OK;
	}

	int bind_any()
	{
		return this->bind(INADDR_ANY);
	}

	int bind_any(uint16_t& portno)
	{
		int ret = this->bind(INPORT_ANY);
		if (ret < 0) {
			return (int)Status::BindError;
		}
		ret = ::getsockname(sock, (sockaddr_t*)&self_addr, &self_addr_len);
		if (ret < 0) {
			return (int)Status::GetSockNameError;
		}
		portno = ntohs(self_addr.sin_port);
		return (int)Status::OK;
	}

	int broadcast(int opt)
	{
		int ret = ::setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (const char*)&opt, sizeof(opt));
		if (ret < 0) {
			return (int)Status::SetSockOptError;
		}
		return (int)Status::OK;
	}

	int close()
	{
		if (sock >= 0) {
#ifdef _WIN32
			int ret = ::shutdown(sock, SD_BOTH);
#else
			int ret = ::shutdown(sock, SHUT_RDWR);
#endif
			if (ret < 0) {
				return (int)Status::ShutdownError;
			}
#ifdef _WIN32
			ret = ::closesocket(sock);
#else
			ret = ::close(sock);
#endif
			if (ret < 0) {
				return (int)Status::CloseError;
			}
			sock = -1;
		}
		return (int)Status::OK;
	}

public:
	template <typename T, typename = typename
		std::enable_if<sizeof(typename T::value_type) == sizeof(uint8_t)>::type>
	int send(const T& message, const IPv4& ipaddr)
	{
		sockaddr_in_t peer_addr = ipaddr;
		socklen_t peer_addr_len = sizeof(peer_addr);
		int ret = ::sendto(sock,
			(const char*)message.data(), message.size(), 0,
			(sockaddr_t*)&peer_addr, peer_addr_len);
		if (ret < 0) {
			return (int)Status::SendError;
		}
		return ret;
	}

	template <typename T, typename = typename
		std::enable_if<sizeof(typename T::value_type) == sizeof(uint8_t)>::type>
	int recv(T& message, IPv4& ipaddr)
	{
		sockaddr_in_t peer_addr;
		socklen_t peer_addr_len = sizeof(peer_addr);
		typename T::value_type buffer[10 * 1024];
		int ret = ::recvfrom(sock,
			(char*)buffer, sizeof(buffer), 0,
			(sockaddr_t*)&peer_addr, &peer_addr_len);
		if (ret < 0) {
			return (int)Status::RecvError;
		}
		ipaddr = peer_addr;
		message = { std::begin(buffer), std::begin(buffer) + ret };
		return ret;
	}

	template <typename T>
	int send_broadcast(const T& message, uint16_t portno)
	{
		// // UPnP
		// std::string msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: ssockp:discover\r\nST: ssockp:all\r\nMX: 1\r\n\r\n";
		IPv4 ipaddr = IPv4::Broadcast(portno);
		int ret = this->send(message, ipaddr);
		return ret;
	}

	template <typename T>
	int send_loopback(const T& message, uint16_t portno)
	{
		IPv4 ipaddr = IPv4::Loopback(portno);
		int ret = this->send(message, ipaddr);
		return ret;
	}

	int interrupt()
	{
		int ret = ::getsockname(sock, (sockaddr_t*)&self_addr, &self_addr_len);
		if (ret < 0) {
			return (int)Status::GetSockNameError;
		}
		uint16_t portno = ntohs(self_addr.sin_port);
		IPv4 ipaddr = IPv4::Loopback(portno);
		ret = this->send(""s, ipaddr);
		return ret;
	}

public:
	enum class Status : int
	{
		OK = 0,
		SocketError = -1,
		OpenError = SocketError,
		CloseError = -2,
		ShutdownError = -3,
		BindError = -4,
		SetSockOptError = -5,
		GetSockNameError = -6,
		SendError = -7,
		RecvError = -8,
		// AddressError = -66,
	};

public:
	struct IPv4
	{
		std::array<uint8_t, 4> octets{};
		uint16_t port{};

	public:
		IPv4()
		{
		}

		IPv4(const std::string& ipaddr, uint16_t portno)
		{
			int ret = ::inet_pton(AF_INET, ipaddr.c_str(), (uint32_t*)octets.data());
			if (ret > 0) {
				port = portno;
			} else {
				// throw std::runtime_error(Status::AddressError)
			}
		}

		IPv4(const sockaddr_in_t& addr_in)
		{
			*(uint32_t*)octets.data() = addr_in.sin_addr.s_addr;
			port = ntohs(addr_in.sin_port);
		}

		operator sockaddr_in_t() const {
			sockaddr_in_t addr_in;
			std::memset(&addr_in, 0, sizeof(addr_in));
			addr_in.sin_family = AF_INET;
			addr_in.sin_addr.s_addr = *(uint32_t*)octets.data();
			addr_in.sin_port = htons(port);
			return addr_in;
		}

private:
		IPv4(uint32_t ipaddr, uint16_t portno)
		{
			*(uint32_t*)octets.data() = htonl(ipaddr);
			port = portno;
		}

public:
		static IPv4 Loopback(uint16_t portno) { return IPv4{ INADDR_LOOPBACK, portno }; }
		static IPv4 Broadcast(uint16_t portno) { return IPv4{ INADDR_BROADCAST, portno }; }

	public:
		bool operator==(const IPv4& other) const {
			return this->octets == other.octets && this->port == other.port;
		}

		bool operator!=(const IPv4& other) const {
			return !(*this == other);
		}

	public:
		const uint8_t& operator[](size_t octet) const { return octets[octet]; }
		uint8_t& operator[](size_t octet) { return octets[octet]; }

	public:
		std::string addr_string() const {
			return std::to_string(octets[0]) +
			"."s + std::to_string(octets[1]) +
			"."s + std::to_string(octets[2]) +
			"."s + std::to_string(octets[3]);
		}

		std::string port_string() const {
			return std::to_string(port);
		}

		std::string to_string() const {
			return this->addr_string() + ":"s + this->port_string();
		}

		operator std::string() const { return this->to_string(); }
	};

#ifdef _WIN32
public:
	static WSADATA* WSAInit()
	{
		static WSADATA wsa;
		static struct WSAContext {
			WSAContext(WSADATA* wsa) {
				WSAStartup(0x0202, wsa);
			}
			~WSAContext() {
				WSACleanup();
			}
		} context{ &wsa };
		return &wsa;
	}
#endif
};

using UDPstatus = UDPsocket::Status;
