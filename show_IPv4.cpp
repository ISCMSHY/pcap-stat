#include <pcap/pcap.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <map>
#include <string>
#include <vector>
#include <cstring>
#include <utility>
#include <typeinfo>
using namespace std;

map<uint32_t, vector<int>> IPv4_map;

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

void confirm_node(unsigned int ip, int packetsize, int value){
	if(IPv4_map.find(ip) == IPv4_map.end()){
		if(value == 0)
			IPv4_map[ip] = vector<int>{1, packetsize, 0, 0};
		else
			IPv4_map[ip] = vector<int>{0, 0, 1, packetsize};
	}
	else{
		if(value == 0){
			IPv4_map[ip][0]++;
			IPv4_map[ip][1] += packetsize;
		}
		else{
			IPv4_map[ip][2]++;
			IPv4_map[ip][3] += packetsize;
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
	unsigned int src_ip;
	unsigned int dst_ip;
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
		//printf("Src address: %s\n", inet_ntoa(iph->ip_src));
		//printf("Dst address: %s\n", inet_ntoa(iph->ip_dst));
		src_ip = inet_stoi(iph->ip_src);
		dst_ip = inet_stoi(iph->ip_dst);

		confirm_node(src_ip, packetsize, 0);
		confirm_node(dst_ip, packetsize, 1);
	}
	map<uint32_t, vector<int>>::iterator iter;
	printf("[Address]\t[TX packets|TX bytes|RX packets|RX bytes]\n");
	for(iter = IPv4_map.begin(); iter != IPv4_map.end(); iter++){
		cout << "[" << inet_itos(iter->first) << "]";
		printf("\t[%d\t%d\t%d\t%d]\n", iter->second[0], iter->second[1], iter->second[2], iter->second[3]);
	}
	return 0;
}
