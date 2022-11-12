/*
	This is a simple DNS tool made for unix systems
	that uses UDP protocol to resolve host's ip.
	It uses 1.1.1.1 server by default and operates at port 53.
	Author: https://github.com/RedHopper
*/
#include<iostream>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h> // close()
#include<cstring> // memset(), memcpy()
#include<vector>

void print_hex(const unsigned char* bytes, int size) // Used for packet debugging
{
	for (int i{}; i < size; ++i)
	{
		printf("%02x ", static_cast<int>(bytes[i]));
		if (i && i%2 == 1) std::cout << "\n";
	}
	if ((size-1)%2 != 1) std::cout << "\n";
}

void vector_from_buffer(const unsigned char* buffer, int size, std::vector<unsigned char>* vec) // Make a vector from server's response for straightforward memory management
{
	vec->clear();
	for (int i{}; i < size; ++i)
	{
		vec->push_back(buffer[i]);
	}
}

std::vector<unsigned char> host_to_packet(std::string host) // Used to make QNAME DNS section from host string
{
	std::vector<unsigned char> result;
	if (host[0] == '.')
	{
		std::cerr << "[*] Error: bad host: " << host << "\n";
		return result;
	}
	std::string cache;
	for (int i{}; i < host.size(); ++i)
	{
		if (host[i] == '.')
		{
			result.push_back(cache.size());
			for (int a{}; a < cache.size(); ++a) result.push_back(cache[a]);
			cache = "";
			continue;
		}
		cache += host[i];
	}
	if (cache.size() > 0)
	{
		result.push_back(cache.size());
		for (int i{}; i < cache.size(); ++i) result.push_back(cache[i]);
	}
	result.push_back(0x00); // Zero byte is used to declare QNAME section's end;
	return result;
}

int main(const int argc, const char** argv)
{
	if (argc != 2)
	{
		std::cerr << "Usage: " << argv[0] << " <host name>\n";
		return 1;
	}
	std::string host_name{argv[1]};
	constexpr int header_size{12};
	unsigned char id[2]{};
	id[0] = 0xAD; // Arbitrary id;
	id[1] = 0xDA;
	unsigned char header[10]{};
	header[0] = 0b0000'0001; // RD flag set to 1; enables recursion;
	header[1] = 0b0000'0000;
	header[3] = 0x01; // Number of questions; since we're asking only for single domain resolution it is set to 1;

	std::vector<unsigned char> qname{host_to_packet(host_name)};
	unsigned char qtype_qclass[4]{0x00, 0x01, 0x00, 0x01};
	int request_size{static_cast<int>(16+qname.size())}; // to simplify code value 16 is used to represent packet's part, which size is always unchanged; HEADER+QTYPE+QCLASS;
	unsigned char* request {new unsigned char[request_size]{}};
	memcpy(request, id, sizeof(id));
	memcpy(request+sizeof(id), header, sizeof(header));
	memcpy(request+sizeof(id)+sizeof(header), &qname[0], qname.size());
	memcpy(request+sizeof(id)+sizeof(header)+qname.size(), qtype_qclass, sizeof(qtype_qclass));
	//print_hex(request, request_size); //Debugging operation that has been used for packet inspection;

	int sock_fd{socket(AF_INET, SOCK_DGRAM, 0)};
	if (!sock_fd)
	{
		std::cerr << "[*] Error initializing socket\n";
		return 1;
	}
	std::string host{"1.1.1.1"};
	short port{53};
	sockaddr_in server_info{};
	inet_aton(host.c_str(), &server_info.sin_addr);
	server_info.sin_port = htons(port);
	server_info.sin_family = AF_INET;
	if (connect(sock_fd, reinterpret_cast<sockaddr*>(&server_info), sizeof(server_info)) == -1)
	{
		std::cerr << "[*] Error: wasn't able to connect to server\n";
		close(sock_fd);
		return 1;
	}
	if (send(sock_fd, request, request_size, 0) == -1)
	{
		std::cerr << "[*] Error sending message to server\n";
		close(sock_fd);
		return 1;
	}
	unsigned char buffer[64]{}; // 64 bytes is enough to fit at least one host's ip from server's response;
	if (recv(sock_fd, buffer, sizeof(buffer), 0) == -1)
	{
		std::cerr << "[*] Error recieving message from server\n";
		close(sock_fd);
		return 1;
	}
	std::vector<unsigned char> vec_buffer;
	vector_from_buffer(buffer, sizeof(buffer), &vec_buffer);
	bool error{buffer[3] & 0b0000'1111}; // Last four bits of fourth byte in server's response represent error code; RCODE is zero when no errors occured;
	bool same_id{}; // additional check if response's id matches our's;
	if (buffer[0] == id[0] && buffer[1] == id[1]) same_id = true;
	if (error)
	{
		std::cerr << "[*] DNS server reported error while resolving this host's ip\n";
		close(sock_fd);
		return 1;
	} else if (!same_id)
	{
		std::cerr << "[*] DNS server's id is different from ones requested\n";
		close(sock_fd);
		return 1;
	}
	for (int i{}; i < header_size + qname.size() + 16; ++i) //Erasing answer header since all required checks have been done;
	{
		vec_buffer.erase(vec_buffer.begin());
	}
	std::string ip;
	for (int i{}; i < 4; ++i) // Converting ip bytes to human-readable string;
	{
		ip += std::to_string(static_cast<int>(vec_buffer[i]));
		if (i != 3) ip += '.';
	}
	std::cout << argv[1] << " IP: " << ip << "\n";
	close(sock_fd);
	delete[] request;
	return 0;
}
