#include <pcap/pcap.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <map>
#include <string>
#include <vector>
#include <cstring>
#include <utility>
#include <typeinfo>
using namespace std;

map<std::pair<uint32_t, uint16_t>, vector<int>> tcp_map;
map<std::pair<uint32_t, uint16_t>, vector<int>> udp_map;

unsigned int inet_stoi(struct in_addr addr){
	int i = 3;
	unsigned int result = 0;
	char *ip = inet_ntoa(addr);
	char *arr = strtok(ip, ".");
	while(arr != NULL){
		result |= stoi(arr) << i * 8;
		i--;
		arr = strtok(NULL, ".");
	}
	return result;
}

string inet_itos(unsigned int ip){
	int a = 0;
	string result;
	for(int i = 3; i >= 0; i--){
		a = (ip >> i * 8) & 0xFF;
		string k = to_string(a);
		result += k;
		if(i != 0)
			result += ".";
	}
	return result;
}

void confirm_tcpnode(unsigned int ip, unsigned short port, int packetsize, int value){
	if(tcp_map.find(make_pair(ip, port)) == tcp_map.end()){
		// not exist
		if(value == 0)
			tcp_map.insert(std::make_pair(std::make_pair(ip, port), vector<int>{1, packetsize, 0, 0}));
		else
			tcp_map.insert(std::make_pair(std::make_pair(ip, port), vector<int>{0, 0, 1, packetsize}));
	}
	else{
		// exists
		if(value == 0){
			tcp_map[make_pair(ip, port)][0]++;
			tcp_map[make_pair(ip, port)][1] += packetsize;
		}
		else{
			tcp_map[make_pair(ip, port)][2]++;
			tcp_map[make_pair(ip, port)][3] += packetsize;
		}
	}
}

void confirm_udpnode(unsigned int ip, unsigned short port, int packetsize, int value){
	if(udp_map.find(make_pair(ip, port)) == udp_map.end()){
		if(value == 0)
			udp_map.insert(std::make_pair(std::make_pair(ip, port), vector<int>{1, packetsize, 0, 0}));
		else
			udp_map.insert(std::make_pair(std::make_pair(ip, port), vector<int>{0, 0, 1, packetsize}));
	}
	else{
		if(value == 0){
			udp_map[make_pair(ip, port)][0]++;
			udp_map[make_pair(ip, port)][1] += packetsize;
		}
		else{
			udp_map[make_pair(ip, port)][2]++;
			udp_map[make_pair(ip, port)][3] += packetsize;
		}
	}
}

int main(int argc, char*argv[]){

	pcap_t *pcap_handler;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *packet;
	struct ether_header *ep;
	struct ip *iph;
	struct tcphdr* tcph;
	struct udphdr* udph;
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	int packetsize;

	pcap_handler = pcap_open_offline("test.pcap", errbuf);
	if(pcap_handler == 0){
		printf("pcap file open error: %s\n", errbuf);
	}

	while(pcap_next_ex(pcap_handler, &header, &packet) >= 0){
		if(header->len != header->caplen){
			printf("read pcap failed\n");
			return 0;
		}
		packetsize = header->len;
		//printf("Packet size: %dbytes\n", packetsize);
	
		packet += sizeof(struct ether_header);
		iph = (struct ip*)(packet);
		src_ip = inet_stoi(iph->ip_src);
		dst_ip = inet_stoi(iph->ip_dst);
		if(iph->ip_p == IPPROTO_TCP){
			//printf("TCP!!!\n");
			tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
			src_port = ntohs(tcph->source);
			dst_port = ntohs(tcph->dest);
			confirm_tcpnode(src_ip, src_port, packetsize, 0);
			confirm_tcpnode(dst_ip, dst_port, packetsize, 1);
		}
		else if(iph->ip_p == IPPROTO_UDP){
			//printf("UDP!!!\n");
			udph = (struct udphdr *)(packet + iph->ip_hl * 4);
			src_port = ntohs(udph->source);
			dst_port = ntohs(udph->dest);
			confirm_udpnode(src_ip, src_port, packetsize, 0);
			confirm_udpnode(dst_ip, dst_port, packetsize, 1);
		}
		else
			printf("Other!!!\n");
	}
	map<std::pair<uint32_t, uint16_t>, vector<int>>::iterator iter;
	printf("-------------------------TCP----------------------------\n");
	printf("[       Address|  port|TX packets|TX bytes|RX packets|RX bytes]\n");
	for(iter = tcp_map.begin(); iter != tcp_map.end(); iter++){
		cout << " " << inet_itos((iter->first).first);
		printf(" |%u", (iter->first).second);
		printf(" |%10d|%8d|%10d|%8d]\n", iter->second[0], iter->second[1], iter->second[2], iter->second[3]);
	}
	printf("------------------------ UDP----------------------------\n");
	for(iter = udp_map.begin(); iter != udp_map.end(); iter++){
		cout << "IP: " << inet_itos((iter->first).first);
		printf( "port: %u\t", (iter->first).second);
		printf("[%d|%d|%d|%d]\n", iter->second[0], iter->second[1], iter->second[2], iter->second[3]);
	}
	return 0;
}
