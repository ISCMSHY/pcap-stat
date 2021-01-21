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
using namespace std;

class MACaddress{
	public:
		uint32_t upper;
		uint16_t below;
		MACaddress(uint32_t _upper, uint16_t _below) : upper(_upper), below(_below){}
		bool operator<(const MACaddress& rhs) const{
			if(upper != rhs.upper)
				return upper < rhs.upper;
			return below < rhs.below;
		}
};

map<MACaddress, vector<int>> macaddress_map;

unsigned int change_upper(unsigned char *address){
	unsigned int result = 0;
	for(int i = 0; i < 4; i++)
		result |= address[i] << 8 * (3 - i);
	return result;
}
unsigned short change_below(unsigned char *address){
	unsigned short result = 0;
	for(int i = 0; i < 2; i++)
		result |= address[4 + i] << 8 * (1 - i);
	return result;
}

void confirm_node(unsigned int upper, unsigned short below, int packetsize, int value){
	if(macaddress_map.find(MACaddress(upper, below)) != macaddress_map.end()){
		// there exist
		if(value == 0){
			macaddress_map[MACaddress(upper, below)][0]++;
			macaddress_map[MACaddress(upper, below)][1] += packetsize;
		}
		else{
			macaddress_map[MACaddress(upper, below)][2]++;
			macaddress_map[MACaddress(upper, below)][3] += packetsize;
		}
	}
	else{
		// there not exist
		if(value == 0)
			macaddress_map[MACaddress(upper, below)] = vector<int> {1, packetsize, 0, 0};
		else
			macaddress_map[MACaddress(upper, below)] = vector<int> {0, 0, 1, packetsize};
	}
}

void print_mac(MACaddress index){
	printf("[%.2x.%.2x.%.2x.%.2x.%.2x.%.2x]\t", index.upper>>24&0xFF, index.upper>>16&0xFF, index.upper>>8&0xFF, index.upper&0xFF, index.below>>8&0xFF, index.below&0xFF);
}

void ether_itos(MACaddress index){
	int a = 0;
	string result;
	for(int i = 0; i < 4; i++){
		//printf("%x\n", index.upper >> 8 * (3 - i) & 0xFF);
		a = (index.upper >> 8 * (3 - i)) & 0xFF;
		string k = to_string(a);
		cout << k << endl;
	}
	//printf("%u\n", index.upper);
	//return result
}

int main(int argc, char*argv[]){
	pcap_t *pcap_handler;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *packet;
	struct ether_header *ep;
	struct ip *iph;
	unsigned int dhost_upper;
	unsigned int shost_upper;
	unsigned short dhost_below;
	unsigned short shost_below;
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
	
		ep = (struct ether_header*)(packet);
		//printf("Src macaddress: %s\n", ether_ntoa((struct ether_addr *)ep->ether_shost));
		//printf("Dst macaddress: %s\n", ether_ntoa((struct ether_addr *)ep->ether_dhost));
		dhost_upper = change_upper(ep->ether_dhost);
		shost_upper = change_upper(ep->ether_shost);
		dhost_below = change_below(ep->ether_dhost);
		shost_below = change_below(ep->ether_shost);
		confirm_node(shost_upper, shost_below, packetsize, 0);
		confirm_node(dhost_upper, dhost_below, packetsize, 1);
	}
	map<MACaddress, vector<int>>::iterator iter;
	printf("[     Address     ]\t[TX packets|TX bytes|RX packets|RX bytes]\n");
	for(iter = macaddress_map.begin(); iter != macaddress_map.end(); iter++){
		print_mac(iter->first);
		//cout << "[" << ether_itos(iter->first) << "]";
		printf("[%10d|%8d|%10d|%8d]\n", iter->second[0], iter->second[1], iter->second[2], iter->second[3]);
	}
	return 0;
}
