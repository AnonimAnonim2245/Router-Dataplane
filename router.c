#include <arpa/inet.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "list.h"
#include "protocols.h"
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP 0x0800
#define TTL 64
#define IPV4SIZE 31
struct arp_header *arp_hdr;
struct route_table_entry *rtable;
int rtable_len;
typedef struct arp_table_entry arp_table;
arp_table *mac_table;
int mac_table_len;
struct trie* head_trie;
queue queue_packets = NULL;

uint32_t max = 0xFFFFFFFF;
char hello[1600] = {0};
char packet[MAX_PACKET_LEN]={0};
uint8_t max_mac[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
struct arp_packet{
	char* packet;
	uint32_t dest_ip;
};

void ICMP_ECHO(struct iphdr* ip_hdr, size_t packet_len, int interface){
	struct icmphdr* icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = 0;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	int d_ip = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = d_ip;
	icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));
	send_to_link(interface, packet,packet_len);

}
/**
 * acesta functie este facuta pentru a verifica daca in mod special daca lungimea packetului
 * este mai mare decat payloadul de 64 biti si numarul de biti al IP-headerului
 * se aplica lui timeout sau unreachable
*/
void ICMP_32(struct iphdr* ip_hdr, size_t packet_len, int interface, uint8_t type){
	size_t ip_hlen_32_b = ip_hdr->ihl * sizeof((char)32); // numarul de biti al headerului
	//ip_hdr->ihl reprezinta numarul de cuvinte de 32

	if(packet_len < ip_hlen_32_b + sizeof((char)64)){
		return;
	}
	struct icmphdr* icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = type; //depinde daca este timeout sau unreachable
	icmp_hdr->code = 0; //specific ICMP
	icmp_hdr->checksum = 0; 
	struct ether_header *eth_hdr = (struct ether_header *) packet;
	eth_hdr->ether_type = htons(ETHERTYPE_IP);
	uint8_t cop_ether[6];
	memcpy(cop_ether, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, cop_ether, 6);


	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->ttl = TTL; // resetam ttl, mai ales cand este timeout
	ip_hdr->tot_len = htons(ntohs(ip_hdr->tot_len) + sizeof(struct icmphdr));
	//ntohs converts to normal format and htons converts to network format
	//we do this in order to include the imcp header in the total length
	ip_hdr->protocol = 1; /// protocol utilizat la icmp
	ip_hdr->check = 0;
	ip_hdr->check = checksum((uint16_t *)ip_hdr, ip_hlen_32_b);
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + 8, ip_hdr, 8);

	icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));
	send_to_link(interface, packet, packet_len+8);
}
void ICMP_TTL(struct iphdr* ip_hdr, size_t packet_len, int interface){

	ICMP_32(ip_hdr, packet_len, interface, 11); // type care este 11 pt ttl
	
}
void ICMP_HOSTUN(struct iphdr* ip_hdr, size_t packet_len, int interface){
	ICMP_32(ip_hdr, packet_len, interface, 3); // type care este 3 pt unreachable
}

struct trie{
	struct route_table_entry *route;
	struct trie* path[2]; 
};
struct trie* element(struct trie* node){ ///cream o noua structura trie
	node = malloc(sizeof(struct trie));
	node->path[0]=NULL;
	node->path[1]=NULL;
	node->route=NULL;
	DIE(node == NULL, "memory");
	return node;
}

void make_trie(struct route_table_entry* route ){
	

	if(head_trie == NULL){
		head_trie = element(head_trie);
	}

	struct trie* node = head_trie;
	uint32_t mask_adr = ntohl(route->mask); 
	uint32_t prefix = ntohl(route->prefix);
	int pos=IPV4SIZE;
	while(pos>=0 && mask_adr!=0){

		uint32_t number = (prefix & 1<<pos);
		number = number!=0 ? 1 : 0;
		if (node->path[number] == NULL) {
			node->path[number] = element(node->path[number]);
		}
		node = node->path[number];
		
		
		uint32_t mask_neg = (~mask_adr)+max+1;
		uint32_t b=((mask_adr>>1) & (~mask_neg));
	    mask_adr=b; ///aceasta structura ne permite sa eliminam cifra curenta
		 /// 11100 -> 1100

 		if(pos>=0 && mask_adr==0){ /// aici verificam daca s-a terminat masca sau positia in
		///care perutam bitii
		    if (node->route == NULL) {
        		node->route = route;
    		}
			continue;
		}
		
		
		pos--;
	
	}
	


}

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	/* TODO 2.2: Implement the LPM algorithm */

    int pos = IPV4SIZE;
	struct trie* node_dest = head_trie;
	struct route_table_entry* best_route=NULL;
	
	while(node_dest!=NULL){
		if(node_dest->route!=NULL){
		best_route = node_dest->route;
		}	
		uint32_t number = ntohl(ip_dest) & 1<<pos; ///verifiam daca cifra curenta este 1 sau 0 
		number = number!=0 ? 1 : 0;
		node_dest = node_dest->path[number];
		pos--;
	}
//	printf("\n%d\n",best_route->interface);
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
	 * the rtable are in network order already */
	return best_route;
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
	 * the rtable are in network order already */
}


arp_table *get_mac_entry(uint32_t given_ip) {
	/* TODO 2.4: Iterate through the MAC table and search for an entry
	 * that matches given_ip. */

	/* We can iterate thrpigh the mac_table for (int i = 0; i <
	 * mac_table_len; i++) */
	for(int i=0;i<mac_table_len; i++){
		if(mac_table[i].ip == given_ip){
			return &mac_table[i];
		}
	}
	return NULL;
}

int is_mac_valid(uint8_t mac1[6], uint8_t mac2[6]){
	
	///verificam daca adresa mac destinatie este egala sau daca este egala cu cea broadcast
	//broadcastul este transmis catre toate dispozitivele(cererile ARP), iar verificare cu interfata a adresei destinatie, daca nu corespunde
	//isi da seama ca packetul nu este destinat ei
	return !memcmp(mac1,mac2,6) || !memcmp(mac1,max_mac,6);
}

void send_arp_request(int interface_best, char* packet_arp, int interface_ip, uint8_t mac_adress[6],size_t *packet_len, int destination_ip){
	struct ether_header* eth_hdr = (struct ether_header*)(packet_arp);
	eth_hdr->ether_type = htons(0x806);
	memcpy(eth_hdr->ether_shost, mac_adress,6);
	memcpy(eth_hdr->ether_dhost,max_mac,6);
	memcpy(packet_arp,eth_hdr,sizeof(struct ether_header));


	struct arp_header* arp_hdr = (struct arp_header*)(packet_arp+sizeof(struct ether_header));
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(ARP_REQUEST);
	arp_hdr->ptype = htons(0x800);
	arp_hdr->spa = interface_best;
	memcpy(arp_hdr->sha,mac_adress,6);
	arp_hdr->tpa = destination_ip;
	memcpy(packet_arp+sizeof(struct ether_header),arp_hdr,sizeof(struct arp_header));
	*packet_len = sizeof(struct ether_header) + sizeof(struct arp_header);
	
}
void send_arp_reply( int interface_ip, uint8_t 	mac_adress[6],size_t *packet_len, uint8_t source_adress[6]){
	struct ether_header* eth_hdr = (struct ether_header*)(packet);
	eth_hdr->ether_type = htons(0x806);

	memcpy(eth_hdr->ether_shost,mac_adress,6);
	memcpy(eth_hdr->ether_dhost,source_adress,6);


	memcpy(packet,eth_hdr,sizeof(struct ether_header));

	struct arp_header* arp_hdr = (struct arp_header*)(packet+sizeof(struct ether_header));

	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(ARP_REPLY);
	arp_hdr->ptype = htons(0x800);

	uint32_t cop_arphdr_ip = arp_hdr->spa;
	arp_hdr->spa = arp_hdr->tpa;
	arp_hdr->tpa = cop_arphdr_ip;

	uint8_t cop_arp_hdr_ha[6];
	memcpy(arp_hdr->tha,arp_hdr->sha,6);
	memcpy(arp_hdr->sha,mac_adress,6);

	
	memcpy(packet+sizeof(struct ether_header),arp_hdr,sizeof(struct arp_header));
	*packet_len = sizeof(struct ether_header) + sizeof(struct arp_header);
	
}

void add_arp_table(uint32_t ip, uint8_t mac[6]){
	mac_table[mac_table_len].ip = ip;
	memcpy(mac_table[mac_table_len].mac, mac, 6);
	mac_table_len++;
	///ADAUGAM ELEMENT IN ARP TABLE
}

uint16_t update_checksum(int original_checksum){
	int new_check = ntohs(original_checksum+1);
	return ntohs((uint16_t)(new_check));
}

void recv_arp_reply(uint32_t ip, uint8_t mac[6],int interface, struct ether_header* ether_hdr){
	add_arp_table(ip, mac);

	while(!is_head_null(queue_packets) && queue_empty(queue_packets) == 0){
		struct arp_packet* packet = return_head(queue_packets);
		struct ether_header *eth_hdr = (struct ether_header *) packet->packet;
		struct arp_header *arp_hdr = (struct arp_header *)(packet->packet + sizeof(struct ether_header));

		struct route_table_entry *best_route = get_best_route(packet->dest_ip);
		arp_table *mac_dest = get_mac_entry(best_route->next_hop);
		if(mac_dest==NULL){
			next_head(queue_packets);
			continue;
		}

		
		uint8_t mac_src[6];
		get_interface_mac(best_route->interface, mac_src);
		memcpy(eth_hdr->ether_dhost, mac_dest->mac, 6);
		memcpy(eth_hdr->ether_shost, mac_src, 6);
		send_to_link(best_route->interface, packet->packet, sizeof(packet));
		queue_deq(queue_packets);
	}
}

int main(int argc, char *argv[])
{
	int interface;
	size_t packet_len;
	init(argc - 2, argv + 2);

	/* Don't touch this */
	//printf("0:\n");

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 9000000);
	
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	mac_table = malloc(sizeof(arp_table) * 9000000);
	DIE(mac_table == NULL, "memory");
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);

	mac_table_len = parse_arp_table("arp_table.txt",mac_table);
	queue_packets = queue_create(); //crearea cozii
	DIE(queue_packets == NULL, "memory");
	for(int i=0;i<rtable_len; i++){
		make_trie(&rtable[i]); ///functia pentru trie
	}
	int i=0;
	while (1) {
		/* We call get_packet to receive a packet. get_packet returns
		the interface it has received the data from. And writes to
		len the size of the packet. */
		//printf("1:\n");
		interface = recv_from_any_link(packet, &packet_len);
		//printf("INTERFACE %d\n",interface);
		DIE(interface < 0, "get_message");

		uint8_t interface_mac[6];
		get_interface_mac(interface, interface_mac);
		int interface_ip = inet_addr(get_interface_ip(interface));
		//extragem interfata ip si mac
		/* Extract the Ethernet header from the packet. Since protocols are
		 * stacked, the first header is the ethernet header, the next header is
		 * at m.paylo	ad + sizeof(struct ether_header) */
		struct ether_header *eth_hdr = (struct ether_header *) packet;
		
		if(!is_mac_valid(eth_hdr->ether_dhost, interface_mac)){
			continue;
		}
		
		

		if(eth_hdr->ether_type == ntohs(ETHERTYPE_IP)){
			struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
						

			if (interface_ip == ip_hdr->daddr) {
				struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
				if(icmp_hdr->type == 8 && icmp_hdr->code==0) {
					ICMP_ECHO(ip_hdr, packet_len, interface);
					continue;
				}
				
			}
			if(!checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))){ ///daca checksumul este zero, datele sunt okay, daca nu, a fost o eroare
				struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
				///cautam best_route-ul in tabela pentru minimizarea latentei, optimizare


				if(best_route == NULL){		
					ICMP_HOSTUN(ip_hdr, packet_len, interface);
					continue;
				}

				if(ip_hdr->ttl <=1){
					ICMP_TTL(ip_hdr, packet_len, interface);
					continue;
				}

				ip_hdr->ttl--;


				ip_hdr->check = update_checksum(ip_hdr->check);					
				arp_table *mac_entry = get_mac_entry(best_route->next_hop);
			
				int cop_len = packet_len;

				if(mac_entry==NULL){


					struct arp_packet *packet_arp = (struct arp_packet*)malloc(sizeof(struct arp_packet));
					packet_arp->packet = (char*)packet;
					packet_arp->dest_ip = best_route->next_hop;
					queue_enq(queue_packets, packet_arp);
					///bagam in coada in caz ca nu gasim in arp table, 	
					
					int ip_best_interface = inet_addr(get_interface_ip(best_route->interface));
					uint8_t best_interface_mac[6];
					///adresa interfetei mac care va fi folosita ca si sursa
					get_interface_mac(best_route->interface, best_interface_mac);

					/// in cadrul arp_request, noi avea ca si arp destinatie la ip,
					///next hopul best route, care reprezinta un intermediar
					/// pentru a putea a ajunge la destinatie dorita la care nu putem ajunge direct
					/// iar pentru optimal, ne bagam pe interfata best route-ului
					/// in aceasta faza nu stim adresa mac destinatie, si de aceea facem un arp request pentru a intreba
					/// care ne va ajuta in determinarea adresei mac destinatie
					send_arp_request(ip_best_interface,packet,interface_ip, best_interface_mac, &packet_len, best_route->next_hop);

					send_to_link(best_route->interface, packet, packet_len);
					continue;
				}

				memcpy(eth_hdr->ether_dhost, mac_entry->mac, 6);
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);
				send_to_link(best_route->interface, packet,packet_len);
						
				
			}
		}
		else if(eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)){
			arp_hdr = (struct arp_header *)(packet + sizeof(struct ether_header));
			if(arp_hdr->op == htons(ARP_REQUEST)){
				size_t cop_packet = packet_len;			
				//adresa tha este completata cu adresa mac a sursei
				//pentru a confirma ca adresa arp care a solicitat arp request si-a primit
				//raspunsul
				send_arp_reply(interface_ip, interface_mac, &packet_len, arp_hdr->sha);
				send_to_link(interface, packet, packet_len);
				packet_len = cop_packet;

			}
			else if(arp_hdr->op == htons(ARP_REPLY)){
				//acum procesam raspunsul arp, si adaugam adresele sursa
				//in arp table, si dupa cautam in coada daca exista vreun packet
				// a carui adresa ip next hop sa corespunda cu adresa ip din arp reply
				//si trimitem packetul si il eliminam din coada
				recv_arp_reply(arp_hdr->spa, arp_hdr->sha,interface, eth_hdr);
			}
			else{
				printf("Invalid");
			}


		}
		else{
			printf("Invalid");
		}

		/* TODO 2.1: Check the ip_hdr integrity using ip_checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) */

		/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */

		/* TODO 2.3: Check TTL >= 1. Update TLL. Update checksum  */

		/* TODO 2.4: Update the ethernet addresses. Use get_mac_entry to find the destination MAC
		 * address. Use get_interface_mac(m.interface, uint8_t *mac) to
		 * find the mac address of our interface. */
		  
		// Call send_to_link(best_router->interface, packet, packet_len);
	}
}
