#include "protocols.h"
#include "queue.h"
#include "trie.h"
#include "lib.h"

#include <arpa/inet.h>
#include <string.h>

#define DROP_PACKET(condition) do { if (condition) return; } while (0)

#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV4 0x0800

#define BROADCAST 0x1
#define LOCAL 0x2
#define UNICAST 0x3

#define REQUEST 0x1
#define REPLY 0x2

#define ARP_TABLE_SIZE 100

struct header {
	struct ether_hdr ethernet_header;
	union {
		struct {
			struct ip_hdr ipv4_header;
			struct icmp_hdr icmp_header;
		} ip;
		struct arp_hdr arp_header;
	} payload;
} __attribute__((packed));

struct packet {
	struct header *header;
	size_t len;
	struct route_table_entry *entry;
};

/*
	Print Functions [DEBUG]
*/
void print_ip(uint32_t ip) 
{
	printf("%u.%u.%u.%u\n", ip >> 24, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

void print_mac(uint8_t *mac)
{
	printf("MAC: %x.%x.%x.%x.%x.%x\n", 
		mac[0], 
		mac[1], 
		mac[2],
		mac[3],
		mac[4],
		mac[5]
	);
}

void print_ether_header(struct header *header)
{
	// Print Source MAC
	printf("SRC ");
	print_mac(header->ethernet_header.ethr_shost);

	// Print Destination MAC
	printf("DST ");
	print_mac(header->ethernet_header.ethr_dhost);

	// Print Ethertype
	printf("Ethertype: 0x0%x\n", ntohs(header->ethernet_header.ethr_type));
}

void print_ipv4_header(struct header *header)
{
	printf("Version: %u\n", header->payload.ip.ipv4_header.ver);
	printf("IHL: %u\n", header->payload.ip.ipv4_header.ihl);
	printf("Type of Service: %u\n", ntohs(header->payload.ip.ipv4_header.tos));
	printf("Total Length: %u\n", ntohs(header->payload.ip.ipv4_header.tot_len));
	printf("ID: %u\n", ntohs(header->payload.ip.ipv4_header.id));
	printf("Frag: %u\n", header->payload.ip.ipv4_header.frag);
	printf("TTL: %u\n", header->payload.ip.ipv4_header.ttl);
	printf("Protocol: %u\n", header->payload.ip.ipv4_header.proto);
	printf("Checksum: %u\n", ntohs(header->payload.ip.ipv4_header.checksum));

	printf("IP SRC: ");
	print_ip(ntohl(header->payload.ip.ipv4_header.source_addr));

	printf("IP DST: ");
	print_ip(ntohl(header->payload.ip.ipv4_header.dest_addr));
}

void print_arp_header(struct header *header)
{
	printf("Hardware Type: %u\n", ntohs(header->payload.arp_header.hw_type));
	printf("Protocol Type: %x\n", ntohs(header->payload.arp_header.proto_type));
	printf("Hardware Size: %u\n", header->payload.arp_header.hw_len);
	printf("Protocol Size: %u\n", header->payload.arp_header.proto_len);
	printf("Opcode: %u\n", ntohs(header->payload.arp_header.opcode));
	printf("Sender ");
	print_mac(header->payload.arp_header.shwa);
	printf("Sender ");
	print_ip(ntohl(header->payload.arp_header.sprotoa));
	printf("Target ");
	print_mac(header->payload.arp_header.thwa);
	printf("Target ");
	print_ip(ntohl(header->payload.arp_header.tprotoa));
}

/*
	MAC Utils
*/
bool compare_mac(uint8_t mac_1[6], uint8_t mac_2[6])
{
	for (int i = 0; i < 6; i++) {
		if (mac_1[i] != mac_2[i])
			return false;
	}

	return true;
}

void copy_mac(uint8_t *mac_src, uint8_t *mac_dst)
{
	for (int i = 0; i < 6; i++) {
		mac_dst[i] = mac_src[i];
	}
}

/*
	Route Table & LPM Utils
*/
struct trie_node* read_route_table(const char *path) 
{
	// Open File
	FILE *fp = fopen(path, "r");
	char *p, line[64];	

	// Route Trie
	struct trie_node *route_trie = createNode();

	int i;
	// Iterate through all the lines
	while (fgets(line, sizeof(line), fp) != NULL) {
		// Tokenize each line
		p = strtok(line, " .");

		// Create Route Entry
		struct route_table_entry *entry = (struct route_table_entry *)malloc(sizeof(struct route_table_entry));

		// Parse each element from line
		i = 0;
		while (p != NULL) {
			// Parse Prefix
			if (i < 4)
				*(((unsigned char *)&entry->prefix) + i % 4) = (unsigned char)atoi(p);

			// Parse Next-hop
			if (i >= 4 && i < 8)
				*(((unsigned char *)&entry->next_hop) + i % 4) = atoi(p);

			// Parse Mask
			if (i >= 8 && i < 12)
				*(((unsigned char *)&entry->mask) + i % 4) = atoi(p);

			// Parse Interface
			if (i == 12)
				entry->interface = atoi(p);
			
			// Get Next Token
			p = strtok(NULL, " .");
			i++;
		}

		// Add Entry in Trie
		insert(route_trie, entry);
	}

	return route_trie;
}

struct route_table_entry* get_LPM(struct trie_node *route_table, uint32_t target_ip)
{
	struct trie_node *current = route_table;
    struct route_table_entry *best_entry = NULL;

    // Convert - Host Order
    uint32_t ip = ntohl(target_ip);

    for (int i = 0; i < 32; i++) {
        // Candidate
        if (current->entry != NULL) {
            best_entry = current->entry;
        }

        // Determine direction based on the i-th bit
        int index = (ip >> (31 - i)) & 0x1;

        // Stop
        if (current->children[index] == NULL) {
            break; 
        }

        // Next node
        current = current->children[index];
    }
    
    // Check the final node
    if (current != NULL && current->entry != NULL) {
        best_entry = current->entry;
    }

    return best_entry;
}

/*
	Packet Utils
*/
void get_interface_data(size_t interface, uint32_t *router_ip, uint8_t *router_mac)
{
	// Get Router MAC - Host Order
	get_interface_mac(interface, router_mac);
	
	// Get Router IP - Network Order
	struct in_addr addr;

	char *router_ip_str = get_interface_ip(interface);
	inet_aton(router_ip_str, &addr);
	*router_ip = addr.s_addr;
}

int get_destination_type(struct header *header, uint8_t *router_mac)
{
	// Broadcast
	uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	// Check MAC
	if (compare_mac(broadcast_mac, header->ethernet_header.ethr_dhost)) {
		return BROADCAST;
	}

	// Local
	// Check MAC
	if (compare_mac(router_mac, header->ethernet_header.ethr_dhost)) {
		return LOCAL;
	}

	return UNICAST;
}

/*
	Handle IPV4
*/
void handle_icmp_request(
	struct header *header, 
	size_t len, 
	size_t interface)
{
	// Check Checksum
	void *ip_start = (uint8_t *)header + sizeof(struct ether_hdr);
	int res = checksum((uint16_t *)ip_start, sizeof(struct ip_hdr));
	DROP_PACKET(res != 0);

	// Sanity check - Check if packet is ICMP Request
	DROP_PACKET(header->payload.ip.icmp_header.mtype != 8 || header->payload.ip.icmp_header.mcode != 0);

	// Modify ICMP
	header->payload.ip.icmp_header.mtype = 0;
	header->payload.ip.icmp_header.mcode = 0;
	header->payload.ip.icmp_header.check = 0;

	// ICMP Checksum
	uint16_t icmp_len = ntohs(header->payload.ip.ipv4_header.tot_len) - header->payload.ip.ipv4_header.ihl * 4;
	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)((char *)header + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, icmp_len));

	// Modify IPV4
	// Switch IPs Swap
	uint32_t old_src = header->payload.ip.ipv4_header.source_addr;
    uint32_t old_dst = header->payload.ip.ipv4_header.dest_addr;
	header->payload.ip.ipv4_header.source_addr = old_dst;
    header->payload.ip.ipv4_header.dest_addr   = old_src;

	// Set TTL
	header->payload.ip.ipv4_header.ttl = 64;

	// Update Checksum
	struct ip_hdr *ipv4_header = (struct ip_hdr *)((char *)header + sizeof(struct ether_hdr));
	ipv4_header->checksum = 0;
    ipv4_header->checksum = htons(checksum((uint16_t *)ipv4_header, sizeof(struct ip_hdr)));

	// Modify Ethernet
	// Switch MACs Swap
	uint8_t temp_mac[6];
	copy_mac(header->ethernet_header.ethr_shost, temp_mac);
	copy_mac(header->ethernet_header.ethr_dhost, header->ethernet_header.ethr_shost);
	copy_mac(temp_mac, header->ethernet_header.ethr_dhost);

	// Send Packet
	send_to_link(len, (char *)header, interface);
}

void send_icmp_error(
	struct header *header, 
	size_t interface, 
	uint8_t type, 
	uint8_t code)
{
	// Build ICMP Packet
	char buf[MAX_PACKET_LEN];
	struct header *new_packet = (struct header *)buf;

	// Get Router Data
	uint8_t router_mac[6];
    uint32_t router_ip;
    get_interface_data(interface, &router_ip, router_mac);

	// Build Ether Header
	copy_mac(router_mac, new_packet->ethernet_header.ethr_shost);
	copy_mac(header->ethernet_header.ethr_shost, new_packet->ethernet_header.ethr_dhost);
	new_packet->ethernet_header.ethr_type = htons(ETHERTYPE_IPV4);

	// Build IPV4 Header
	struct ip_hdr *ipv4_header = (struct ip_hdr *)((char *)new_packet + sizeof(struct ether_hdr));
	ipv4_header->ver = 4;
	ipv4_header->ihl = 5;
	ipv4_header->tos = 0;
	ipv4_header->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
	ipv4_header->id = htons(4);
	ipv4_header->frag = 0;
	ipv4_header->ttl = 64;
	ipv4_header->proto = 1;
	ipv4_header->source_addr = htonl(router_ip);
	ipv4_header->dest_addr = header->payload.ip.ipv4_header.source_addr;
	ipv4_header->checksum = 0;
	ipv4_header->checksum = htons(checksum((uint16_t *)ipv4_header, sizeof(struct ip_hdr)));
	
	// Build ICMP Header
	struct icmp_hdr *icmp = (struct icmp_hdr *)((char *)new_packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	icmp->mtype = type;
	icmp->mcode = code;
	icmp->check = 0;
	icmp->un_t.echo_t.id = 0;
	icmp->un_t.echo_t.seq = 0;
	
	// Copy Payload
	// Pointer for payload placement
	uint8_t *payload = (uint8_t *)buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);
	// Copy IPV4 header in payload
	memcpy(payload, &header->payload.ip.ipv4_header, sizeof(struct ip_hdr));
	// Copy next 64 bits after IPV4 to payload
	void *data = (uint8_t *)header + sizeof(struct ether_hdr) + sizeof(struct ip_hdr);
	memcpy(payload + sizeof(struct ip_hdr), data, 8);

	// Compute Checksum ICMP
	icmp->check = htons(checksum((uint16_t *)icmp, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8));

	// Send ICMP Error
	size_t total_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;
	send_to_link(total_len, buf, interface);
}

void handle_icmp_dest_unrcbl(
	struct header *header, 
	size_t interface)
{
	// Set ICMP Error Fields
	send_icmp_error(header, interface, 3, 0);
}

void handle_icmp_time_excd(
	struct header *header,
	size_t interface)
{
	// Set ICMP Error Fields
	send_icmp_error(header, interface, 11, 0);
}

void send_arp_request(int interface, uint8_t *router_mac, uint32_t router_ip, uint32_t target_ip)
{
	struct header header;

	// Broadcast
	uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	// Zero
	uint8_t zero_mac[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

	// Build Ether Header
	copy_mac(broadcast_mac, header.ethernet_header.ethr_dhost);
	copy_mac(router_mac, header.ethernet_header.ethr_shost);
	header.ethernet_header.ethr_type = htons(ETHERTYPE_ARP);

	// Build ARP Header
	header.payload.arp_header.hw_type = htons(0x1);
	header.payload.arp_header.proto_type = htons(ETHERTYPE_IPV4);
	header.payload.arp_header.hw_len = 6;
	header.payload.arp_header.proto_len = 4;
	header.payload.arp_header.opcode = htons(REQUEST);
	
	// Set IP Addresses
	header.payload.arp_header.sprotoa = router_ip;
	header.payload.arp_header.tprotoa = target_ip;

	// Set MAC Addresses
	copy_mac(router_mac, header.payload.arp_header.shwa);
	copy_mac(zero_mac, header.payload.arp_header.thwa);
	
	// Send
	size_t len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	send_to_link(len, (char *)&header, interface);
}

void handle_ipv4(
	struct header *header, size_t len, 
	size_t interface, 
	struct trie_node *route_table, 
	struct arp_table_entry *arp_table, int arp_size,
	queue queue)
{
	// Get Router Data
	uint8_t router_mac[6];
	uint32_t router_ip;
	get_interface_data(interface, &router_ip, router_mac);

	// Check MAC Destination
	switch (get_destination_type(header, router_mac)) 
	{
		case BROADCAST:
		case LOCAL:
			break;
		default:
			DROP_PACKET(true);
			break;
	}

	// Check IP Destination -> Handle ICMP Request (Packet for Router)
	if (router_ip == header->payload.ip.ipv4_header.dest_addr) 
	{
		handle_icmp_request(header, len, interface);
		return;
	}

	// ------------ Handle Simple Routing ------------ // 

	// Check Checksum
	void *ip_start = (uint8_t *)header + sizeof(struct ether_hdr);
	int res = checksum((uint16_t *)ip_start, sizeof(struct ip_hdr));
	DROP_PACKET(res != 0);

	// Check TTL
	// ICMP - Time exceeded
	if (header->payload.ip.ipv4_header.ttl < 2)
	{
		handle_icmp_time_excd(header, interface);
		return;
	}

	// Find in Route Table
	struct route_table_entry *entry = get_LPM(route_table, header->payload.ip.ipv4_header.dest_addr);
	// ICMP - Destination unreachable
	if (entry == NULL) 
	{
		handle_icmp_dest_unrcbl(header, interface);
		return;
	}

	// Update TTL
	header->payload.ip.ipv4_header.ttl--;

	// Recompute Checksum
	header->payload.ip.ipv4_header.checksum = 0;
	res = checksum((uint16_t *)ip_start, sizeof(struct ip_hdr));
	header->payload.ip.ipv4_header.checksum = htons(res);

	// Modify L2
	// Get MAC specific to the interface of next-hop
	get_interface_mac(entry->interface, &router_mac[0]);
	
	// Copy Source (Router Interface MAC)
	copy_mac(router_mac, header->ethernet_header.ethr_shost);

	// Copy Destination (Next-hop MAC) & Send-to-link
	for (int i = 0; i < arp_size; i++)
	{
		// We found an IP in ARP Table
		if (arp_table[i].ip == entry->next_hop)
		{
			// Copy MAC address
			copy_mac(arp_table[i].mac, header->ethernet_header.ethr_dhost);
			// Send Packet
			send_to_link(len, (char *)header, entry->interface);
			return;
		}
	}

	// Send ARP
	get_interface_data(entry->interface, &router_ip, router_mac);
	send_arp_request(entry->interface, router_mac, router_ip, entry->next_hop);

	// Add to Queue
	struct packet *packet = (struct packet *)malloc(sizeof(struct packet));
	// Header Copy
	struct header *header_cpy = (struct header *)malloc(len);
	memcpy((char *)header_cpy, (char *)header, len);
	// Build Packet
	packet->header = header_cpy;
	packet->entry = entry;
	packet->len = len;
	// Add
	queue_enq(queue, (void *)packet);
}

/*
	Handle ARP
*/
void handle_arp_reply(struct header *header, size_t interface, struct arp_table_entry *arp_table, int *arp_size)
{
	// Get Router Data
	uint8_t router_mac[6];
    uint32_t router_ip;
    get_interface_data(interface, &router_ip, router_mac);

	// Sanity Check
	// Check Target MAC(router)
	DROP_PACKET(!compare_mac(router_mac, header->payload.arp_header.thwa));
	// Check Target(router) IP
	DROP_PACKET(router_ip != header->payload.arp_header.tprotoa);

	// Add MAC
	copy_mac(header->payload.arp_header.shwa, arp_table[*arp_size].mac);
	// Add IP
	arp_table[*arp_size].ip = header->payload.arp_header.sprotoa; 
	// Increase Table size
	*arp_size = *arp_size + 1;
}

void handle_arp_request(struct header *header, size_t interface, struct arp_table_entry *arp_table, int *arp_size)
{
	// Broadcast
	uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	// Zero
	uint8_t zero_mac[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

	// Get Router Data
	uint8_t router_mac[6];
    uint32_t router_ip;
    get_interface_data(interface, &router_ip, router_mac);

	// Sanity Checks
	// Check Ether Destination MAC
	DROP_PACKET(!compare_mac(broadcast_mac, header->ethernet_header.ethr_dhost));
	// Check Target MAC
	DROP_PACKET(!compare_mac(zero_mac, header->payload.arp_header.thwa));
	// Check Target IP
	DROP_PACKET(router_ip != header->payload.arp_header.tprotoa);

	// Build Reply
	// Set Ether Header
	copy_mac(header->ethernet_header.ethr_shost, header->ethernet_header.ethr_dhost);
	copy_mac(router_mac, header->ethernet_header.ethr_shost);

	// Set ARP Header
	header->payload.arp_header.proto_type = htons(ETHERTYPE_IPV4);
	header->payload.arp_header.opcode = htons(REPLY);

	// Set IP Addresses (Swap IPs)
	uint32_t old_src = header->payload.arp_header.sprotoa;
	uint32_t old_dst = header->payload.arp_header.tprotoa;
	header->payload.arp_header.sprotoa = old_dst;
	header->payload.arp_header.tprotoa = old_src;

	// Set MAC Addresses
	copy_mac(header->payload.arp_header.shwa, header->payload.arp_header.thwa);
	copy_mac(router_mac, header->payload.arp_header.shwa);

	// Send
	size_t len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	send_to_link(len, (char *)header, interface);
}

void handle_arp(
	struct header *header, size_t len, 
	size_t interface, 
	struct trie_node *route_table, 
	struct arp_table_entry *arp_table, int *arp_size, 
	queue queue)
{
	// Sanity Check
	DROP_PACKET(ntohs(header->payload.arp_header.hw_type) != 0x1);
	DROP_PACKET(ntohs(header->payload.arp_header.proto_type) != ETHERTYPE_IPV4);
	DROP_PACKET(header->payload.arp_header.hw_len != 6);
	DROP_PACKET(header->payload.arp_header.proto_len != 4);

	// ARP Type
	switch (ntohs(header->payload.arp_header.opcode))
	{
		case REQUEST:
			handle_arp_request(header, interface, arp_table, arp_size);
			break;
		case REPLY:
			handle_arp_reply(header, interface, arp_table, arp_size);
			// Send All the packets that can be Send
			{
				while (!queue_empty(queue))
				{
					struct packet *packet = queue_deq(queue);
					bool was_sent = false;
					// Copy Destination (Next-hop MAC) & Send-to-link
					for (int i = 0; i < *arp_size; i++)
					{
						// We found an IP in ARP Table
						if (arp_table[i].ip == packet->entry->next_hop)
						{
							// Copy MAC address
							copy_mac(arp_table[i].mac, packet->header->ethernet_header.ethr_dhost);
							// Send Packet
							send_to_link(packet->len, (char *)packet->header, packet->entry->interface);
							// Free Packet
							free(packet->header);
							free(packet);
							// Mark Packet
							was_sent = true;
							break;
						}
					}
					// Check if it was sent
					if (!was_sent)
					{
						// Put back the packet
						queue_enq(queue, packet);
						break;
					}
				}
			}
			break;
		default:
			DROP_PACKET(true);
	}
}

int main(int argc, char *argv[])
{
	// Buffer for Packets
	char buf[MAX_PACKET_LEN];

	// Init Interfaces from args (ex: r-0 r-1)
	init(argv + 2, argc - 2);

	// Init Route Table -> All Entries are Stored in Little-Endian Format
	// Search prefix will be in Little-Endian
	struct trie_node *route_table = read_route_table(argv[1]);
	DIE(route_table == NULL, "route_table_empty");

	// Init ARP Table - MAC Host-Order stored & IP Network-Order
	struct arp_table_entry *arp_table = (struct arp_table_entry *)malloc(ARP_TABLE_SIZE * sizeof(struct arp_table_entry));
	int arp_size = 0;

	// Queue Packet
	queue queue = create_queue();
	
	// Router-loop
	while (1) {
		size_t interface;
		size_t len;

		// Get Packet from Interface
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    	// Implement the router forwarding logic
		struct header *header = (struct header *)buf;

		// Handle Ethertypes
		uint16_t ethertype = ntohs(header->ethernet_header.ethr_type);
		
		switch (ethertype)
		{
		case ETHERTYPE_ARP:
			handle_arp(header, len, interface, route_table, arp_table, &arp_size, queue);
			break;
		case ETHERTYPE_IPV4:
			handle_ipv4(header, len, interface, route_table, arp_table, arp_size, queue);
			break;
		default:
			break;
		}
	}

	free_trie(route_table);
	free(arp_table);
	free(queue);
}
