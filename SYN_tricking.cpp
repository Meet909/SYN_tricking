#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <arpa/inet.h>
#include <thread>
#include <vector>
#include <mutex>


void print_mac_address(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

std::mutex cout_mutex;

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{

	std::unique_lock<std::mutex> lock(cout_mutex, std::defer_lock);
	struct libnet_ethernet_hdr * ethernet;
	struct libnet_ipv4_hdr * ip;
	struct libnet_tcp_hdr * tcp;
	ethernet = (struct libnet_ethernet_hdr *) (packet);
	ip = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H); 
	tcp = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	char errbuf[LIBNET_ERRBUF_SIZE];
        libnet_t *libnet;
        libnet = libnet_init (LIBNET_RAW4, "lo" , errbuf);
        if (libnet == NULL) {
                std::cout << "libnet_init() failed: " << errbuf << std::endl;
                return;
        }

	//We must every time convert variables from network byte order to host order
        uint32_t src_ip = libnet_name2addr4(libnet, inet_ntoa(ip->ip_src), LIBNET_RESOLVE);
        uint32_t dst_ip = libnet_name2addr4(libnet, inet_ntoa(ip->ip_dst), LIBNET_RESOLVE);
        uint16_t src_port = ntohs(tcp->th_sport);
        uint16_t dst_port = ntohs(tcp->th_dport);

	lock.lock();

        // DEBUGGING PUPROSES
        //printf("Captured packet length: %u bytes\n", header->caplen);
        //for (int i = 0; i < header->caplen; ++i)
        //      printf("%02x ", packet[i]);

	std::cout << "Thread ID: (" << std::this_thread::get_id() << "). ";
	std::cout << inet_ntoa(ip->ip_src) << ":" << ntohs(tcp->th_sport) << " -> " << inet_ntoa(ip->ip_dst) << ":"<< ntohs(tcp->th_dport) << std::endl;

	lock.unlock();

	// ***************  Send fake ACK + SYN to mislead scanner *****************
	
  	libnet_seed_prand (libnet);
	libnet_ptag_t tcp_check = 0;
       	libnet_ptag_t ipv4_check = 0;
	
	// Build TCP header
	int32_t seq = 0x10000000;
        tcp_check = libnet_build_tcp(
                dst_port,           		// Source port
                src_port,           		// Destination port
                seq,             		// Sequence number
                htonl(tcp->th_seq) + 1,         // Acknowledgment number
                TH_SYN | TH_ACK,                // Control flags (SYN only)
                libnet_get_prand(LIBNET_PRu16), // Window size
                0,                              // Checksum (0 = autofill)
                0,                              // Urgent pointer
                LIBNET_TCP_H,                   // Total TCP length
                NULL,                           // Payload
                0,                              // Payload size
                libnet,                         // libnet context
                0                               // libnet ptag
        );


    	if (tcp_check == -1)
    	{
      		std::cout << "Unable to build TCP header: " << libnet_geterror (libnet) << std::endl;
      		return;
    	}

	ipv4_check = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H,	// Total length 
		IPTOS_LOWDELAY,			// Type of service bits
		libnet_get_prand(LIBNET_PRu16),	// IP identification number 
		0,				// Fragmentation bits and offset
		libnet_get_prand(LIBNET_PR8),	// Time to live in the network 
		IPPROTO_TCP,			// Upper layer protocol 
		0,				// Checksum (0 for libnet to autofill)
		dst_ip,				// Source IPv4 address (little endian)
		src_ip,				// Destination IPv4 address (little endian)
		NULL,				// Optional payload or NULL
		0,				// Payload length or 0 
		libnet,				// Pointer to a libnet context
		0				// Protocol tag to modify an existing header, 0 to build a new one
	);

	if (ipv4_check == -1)
        {
        	std::cout << "Unable to build TCP header: " << libnet_geterror (libnet) << std::endl;
        	return;
        }

	// Send the packet
	lock.lock();

    	int bytes_written = libnet_write(libnet);
    	if (bytes_written == -1) {
		std::cout << "libnet_write() failed: " << libnet_geterror(libnet) << std::endl;
    	} else {
        	std::cout << "Thread ID: (" << std::this_thread::get_id() << "). " << "Sent " << bytes_written << " bytes." << std::endl;
    	}

	lock.unlock();
}

void captureFromDeviceThread(const std::string& deviceName, const std::string& ip_addr) 
{
	std::unique_lock<std::mutex> lock(cout_mutex, std::defer_lock);
	
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *handle;
	handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);

        if (handle == NULL) {
                return;
        }

        // **** Filtering
	std::string filter_exp = std::string("dst host ") + ip_addr + std::string(" and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0 and not (dst port 80 or dst port 406 or dst port 631)");
        
	/*
        Are destined for the local host.
        Have the SYN flag set (tcp[tcpflags] & tcp-syn != 0), which typically indicates the start of a TCP connection.
        Do not have the ACK flag set (tcp[tcpflags] & tcp-ack = 0), meaning it's the initial SYN packet (not part of an existing connection).
        Are not targeting ports 80, 406, or 631, i.e., exclude HTTP, IPX, and IPP traffic (commonly used by web servers, print services, etc.).
        */

        struct bpf_program fp;          /* The compiled filter */
        bpf_u_int32 net;                /* Our IP */

        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
                return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                return;
        }
        // **** Filtering
	
	lock.lock();  // manually lock
	std::cout << "Started capture on device: " << deviceName << " (Thread ID: " << std::this_thread::get_id() << ")" << std::endl;
        lock.unlock(); // unlock
	
	pcap_loop(handle, -1, callback, NULL);
}

int main(int argc, char* argv[])
{

	if (argc < 2) {
        	
		std::cerr << "Usage: " << argv[0] << " <ip-addr>" << std::endl;
        	return 1;
    	}

	std::string input = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];
    	pcap_if_t *devs;

	if (pcap_findalldevs(&devs, errbuf) == -1) {
		std::cout << "Error: " << errbuf << std::endl;
        	return 1;
    	}

	for (pcap_if_t *d = devs; d; d = d->next) {
		std::cout << "Devices available: " <<  d->name << std::endl;
    	}

	std::vector<std::thread> threads;

    	while (devs) {

        	std::string deviceName(devs->name);
        	threads.emplace_back(captureFromDeviceThread, deviceName, input);
        	devs = devs->next;
    	}

    	for (auto& t : threads) {
        	if (t.joinable()) t.join();
    	}
	
	pcap_freealldevs(devs);
	return 0;
}
