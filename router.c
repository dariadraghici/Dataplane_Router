#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

// routing table
struct route_table_entry *rtable;
int rtable_len;

// ARP table
struct arp_table_entry *arp_table;
int arp_table_len = 0;

struct trie_node {
	struct trie_node *fiu[2];
	struct route_table_entry *entry;
};

static struct trie_node *trie_root;

static struct trie_node *new_trie_node(void)
{
	struct trie_node *node = calloc(1, sizeof(struct trie_node));
	DIE(node == NULL, "calloc failed");
	return node;
}

static int lungime_prefix(uint32_t mask)
{
	int lungime = 0;
	uint32_t primul_bit = (1U << 31);
	while (mask & primul_bit) { // nu poate exista un bit 0 intre doi biti 1
		lungime++;
		mask = mask << 1;
	}
	return lungime;
}

static void trie_insert(struct route_table_entry *entry)
{
	uint32_t prefix = ntohl(entry->prefix);
	uint32_t mask = ntohl(entry->mask);
	int prefix_size = lungime_prefix(mask);

	struct trie_node *node = trie_root;

	for (int i = 31; i > 31 - prefix_size; i--) {
		int bit = (prefix >> i) & 1;
		if (node->fiu[bit] == NULL) // nu exista nod pt bit
			node->fiu[bit] = new_trie_node();
		node = node->fiu[bit];
	}

	if (node->entry == NULL || ntohl(entry->mask) > ntohl(node->entry->mask)) // masca mai specifica sau primul entry pentru prefix
		node->entry = entry;
}

// LPM cu trie
struct route_table_entry *get_best_route(uint32_t target_ip)
{
	uint32_t ip = ntohl(target_ip);
	struct trie_node *node = trie_root;
	struct route_table_entry *best = NULL;

	for (int i = 31; i >= 0; i--) {
		if (node->entry != NULL)
			best = node->entry;

		int bit = (ip >> i) & 1;
		if (node->fiu[bit] == NULL)
			break;
		node = node->fiu[bit];
	}

	if (node != NULL && node->entry != NULL) // mai specific decat best
		best = node->entry;

	return best;
}

// get_mac_entry din tabela ARP
struct arp_table_entry *get_arp_entry(uint32_t given_ip)
{
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip)
			return &arp_table[i];
	}
	return NULL;
}

// request ARP pentru a afla MAC ul asociat unui IP
void send_arp_request(uint32_t target_ip, int out_interface)
{
	char pachet[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)]; // 14 + 28 = 42 bytes
	memset(pachet, 0, sizeof(pachet));

	struct ether_hdr *eth_pachet = (struct ether_hdr *)pachet; // layer 2
	struct arp_hdr *arp_pachet = (struct arp_hdr *)(pachet + sizeof(struct ether_hdr)); // layer 3

	uint8_t mac[6];
	uint32_t ip;
	get_interface_mac(out_interface, mac);
	inet_pton(AF_INET, get_interface_ip(out_interface), &ip); // AF_INET converteste string IP in uint32_t in retea

	memset(eth_pachet->ethr_dhost, 0xFF, 6); // broadcast
	memcpy(eth_pachet->ethr_shost, mac, 6);
	eth_pachet->ethr_type = htons(0x0806);

	arp_pachet->hw_type = htons(1); // 1 = Ethernet
	arp_pachet->proto_type = htons(0x0800);
	arp_pachet->hw_len = 6;
	arp_pachet->proto_len = 4;
	arp_pachet->opcode = htons(1); // 1 = request
	memcpy(arp_pachet->shwa, mac, 6);
	arp_pachet->sprotoa = ip;
	memset(arp_pachet->thwa, 0x00, 6); // MAC dest necunoscut
	arp_pachet->tprotoa = target_ip;

	send_to_link(sizeof(pachet), pachet, out_interface);
}

void send_arp_reply(struct arp_hdr *req, int in_interface)
{
	char pachet[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)]; // 14 + 28 = 42 bytes
	memset(pachet, 0, sizeof(pachet));

	struct ether_hdr *eth_pachet = (struct ether_hdr *)pachet; // layer 2
	struct arp_hdr *arp_pachet = (struct arp_hdr *)(pachet + sizeof(struct ether_hdr)); // layer 3

	uint8_t my_mac[6];
	get_interface_mac(in_interface, my_mac);
	inet_pton(AF_INET, get_interface_ip(in_interface), &arp_pachet->sprotoa); // AF_INET converteste string IP in uint32_t in retea

	memcpy(eth_pachet->ethr_dhost, req->shwa, 6); // MAC sursa din request
	memcpy(eth_pachet->ethr_shost, my_mac, 6);
	eth_pachet->ethr_type = htons(0x0806);

	arp_pachet->hw_type = req->hw_type;
	arp_pachet->proto_type = req->proto_type;
	arp_pachet->hw_len = req->hw_len;
	arp_pachet->proto_len = req->proto_len;
	arp_pachet->opcode = htons(2); // 2 = reply
	memcpy(arp_pachet->shwa, my_mac, 6);
	memcpy(arp_pachet->thwa, req->shwa, 6); // MAC din request
	arp_pachet->tprotoa = req->sprotoa;

	send_to_link(sizeof(pachet), pachet, in_interface);
}

// time exceeded sau destination unreachable
void send_icmp_error(uint8_t tip, uint8_t cod, char *buf_original, size_t len_original, int in_interface)
{
	struct ether_hdr *eth_original = (struct ether_hdr *)buf_original;
	struct ip_hdr *ip_original = (struct ip_hdr *)(buf_original + sizeof(struct ether_hdr)); // layer 3

	int lungime_hdr_ip_original = ip_original->ihl * 4; // lungimea header ului IP original
	int lungime_icmp = lungime_hdr_ip_original + 8; // din enunt: primii 64 de biti din payload-ul pachetului original
	size_t lungime_totala = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + lungime_icmp; // header Ethernet + header IP + header ICMP + date ICMP

	char *raspuns = calloc(1, lungime_totala);
	if (raspuns == NULL)
		return;

	struct ether_hdr *eth_nou = (struct ether_hdr *)raspuns;
	memcpy(eth_nou->ethr_dhost, eth_original->ethr_shost, 6);
	get_interface_mac(in_interface, eth_nou->ethr_shost);
	eth_nou->ethr_type = htons(0x0800); // IPv4

	struct ip_hdr *ip_nou = (struct ip_hdr *)(raspuns + sizeof(struct ether_hdr)); // layer 3
	ip_nou->tos = 0;
	ip_nou->frag = 0;
	ip_nou->ver = 4;
	ip_nou->ihl = 5;
	ip_nou->id = 4;
	ip_nou->tot_len = htons((uint16_t)(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + lungime_icmp));
	ip_nou->ttl = 64;
	ip_nou->proto = 1; // ICMP
	ip_nou->checksum = 0;
	inet_pton(AF_INET, get_interface_ip(in_interface), &ip_nou->source_addr);
	ip_nou->dest_addr = ip_original->source_addr;
	ip_nou->checksum = htons(checksum((uint16_t *)ip_nou, sizeof(struct ip_hdr)));

	struct icmp_hdr *icmp_nou = (struct icmp_hdr *)(raspuns + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)); // layer 4
	icmp_nou->mtype = tip;
	icmp_nou->mcode = cod;
	icmp_nou->check = 0;
	icmp_nou->un_t.echo_t.id = 0;
	icmp_nou->un_t.echo_t.seq = 0;
	uint8_t *date_icmp = (uint8_t *)icmp_nou + sizeof(struct icmp_hdr);
	memcpy(date_icmp, ip_original, lungime_icmp);
	icmp_nou->check = htons(checksum((uint16_t *)icmp_nou, sizeof(struct icmp_hdr) + lungime_icmp));

	send_to_link(lungime_totala, raspuns, in_interface);
}

void send_icmp_echo_reply(char *buf, size_t len, int in_interface)
{
	struct ether_hdr *eth = (struct ether_hdr *)buf;
	struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + ip->ihl * 4);

	uint8_t mac[6];
	memcpy(mac, eth->ethr_dhost, 6);
	memcpy(eth->ethr_dhost, eth->ethr_shost, 6);
	memcpy(eth->ethr_shost, mac, 6);

	uint32_t ip_aux = ip->dest_addr;
	ip->dest_addr = ip->source_addr;
	ip->source_addr = ip_aux;

	ip->ttl = 64;
	ip->checksum = 0;
	ip->checksum = htons(checksum((uint16_t *)ip, ip->ihl * 4));
	icmp->mtype = 0;
	icmp->mcode = 0;
	icmp->check = 0;
	int lungime_icmp = ntohs(ip->tot_len) - ip->ihl * 4;
	icmp->check = htons(checksum((uint16_t *)icmp, lungime_icmp));

	send_to_link(len, buf, in_interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	rtable_len = read_rtable(argv[1], rtable);
	DIE(rtable_len < 0, "read_rtable");

	trie_root = new_trie_node();
	for (int i = 0; i < rtable_len; i++)
		trie_insert(&rtable[i]);

	queue coada_de_pachete = create_queue();

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

		uint8_t mac[6];
		uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		get_interface_mac(interface, mac);

		//din enunt: routerul nostru trebuie să considere doar pachetele trimise către el însuși sau către toată lumea ( FF:FF:FF:FF:FF:FF)
		if (memcmp(eth_hdr->ethr_dhost, mac, 6) != 0 && memcmp(eth_hdr->ethr_dhost, broadcast, 6) != 0)
			continue;

		// IPv4 (0x0800) iar ARP (0x0806)
		uint16_t ether_type = ntohs(eth_hdr->ethr_type);

		// ARP
		if (ether_type == 0x0806) {
			if (len < sizeof(struct ether_hdr) + sizeof(struct arp_hdr))
				continue;

			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			uint16_t operatie = ntohs(arp_hdr->opcode);

			if (operatie == 1) { // request
				uint32_t ip;
				inet_pton(AF_INET, get_interface_ip(interface), &ip);
				if (arp_hdr->tprotoa == ip)
					send_arp_reply(arp_hdr, interface);

			} else if (operatie == 2) { // reply
				if (get_arp_entry(arp_hdr->sprotoa) == NULL) {
                    arp_table = realloc(arp_table, (arp_table_len + 1) * sizeof(struct arp_table_entry));
                    DIE(arp_table == NULL, "realloc failed");

                    arp_table[arp_table_len].ip = arp_hdr->sprotoa;
                    memcpy(arp_table[arp_table_len].mac, arp_hdr->shwa, 6);
                    arp_table_len++;
                }

				queue coada = create_queue();
				while (!queue_empty(coada_de_pachete)) {
					char *pachet = queue_deq(coada_de_pachete);

					uint32_t *ip_pachet = (uint32_t *)pachet;
					int *interface_pachet = (int *)(pachet + sizeof(uint32_t));
					size_t *len_pachet = (size_t *)(pachet + sizeof(uint32_t) + sizeof(int));
					char *buf_pachet = pachet + sizeof(uint32_t) + sizeof(int) + sizeof(size_t);

					if (*ip_pachet == arp_hdr->sprotoa) { // asteapta raspunsul ARP pentru IP ul din reply
						struct ether_hdr *eth_resend = (struct ether_hdr *)buf_pachet;
						get_interface_mac(*interface_pachet, eth_resend->ethr_shost);
						memcpy(eth_resend->ethr_dhost, arp_hdr->shwa, 6);
							
						send_to_link(*len_pachet, buf_pachet, *interface_pachet);
					} else { // nu e raspunsul ARP pentru el
						queue_enq(coada, pachet);
					}
				}

				while (!queue_empty(coada)) { // pachetele care asteapta ARP reply pentru alte IP uri
					queue_enq(coada_de_pachete, queue_deq(coada));
				}
			}
			continue;
		}

		if (ether_type != 0x0800) // IPv4
			continue;

		// ether_hdr = 6 MACd + 6 MACs + 2 b type = 14 bytes
		// ip_hdr = 20 bytes
		if (len < sizeof(struct ether_hdr) + sizeof(struct ip_hdr)) // pachet incomplet/ malformat
			continue;

		struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr)); // layer 3

		uint16_t old_check = ip_hdr->checksum;
		ip_hdr->checksum = 0;
		uint16_t new_check = checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4);
		ip_hdr->checksum = old_check;

		if (ntohs(old_check) != new_check)
			continue;

		int destinat_routerului = 0;
		for (int i = 0; i < argc - 2; i++) {
			uint32_t ip_interfata;
			inet_pton(AF_INET, get_interface_ip(i), &ip_interfata);
			if (ip_hdr->dest_addr == ip_interfata) {
				destinat_routerului = 1;
				break;
			}
		}

		if (destinat_routerului) {
			if (ip_hdr->proto == 1) { // raspunde doar la ICMP echo request (ping)
				struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + ip_hdr->ihl * 4); // layer 4
				if (icmp_hdr->mtype == 8 && icmp_hdr->mcode == 0)
					send_icmp_echo_reply(buf, len, interface);
			}
			continue;
		}

		if (ip_hdr->ttl <= 1) {
			send_icmp_error(11, 0, buf, len, interface); // time exceeded
			continue;
		}

		struct route_table_entry *best_route = get_best_route(ip_hdr->dest_addr);
		if (best_route == NULL) {
			send_icmp_error(3, 0, buf, len, interface); // ICMP destination unreachable
			continue;
		}

		ip_hdr->ttl--;
		ip_hdr->checksum = 0;
		ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4));

		struct arp_table_entry *a_entry = get_arp_entry(best_route->next_hop);

		if (a_entry != NULL) { // MAC cunoscut
			get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
			memcpy(eth_hdr->ethr_dhost, a_entry->mac, 6);
			send_to_link(len, buf, best_route->interface);
		} else { // MAC necunoscut
			char *pachet_coada = malloc(sizeof(uint32_t) + sizeof(int) + sizeof(size_t) + MAX_PACKET_LEN);
			DIE(pachet_coada == NULL, "malloc pachet MAC necunoscut");

			uint32_t *target_ip = (uint32_t *)pachet_coada;
			int *target_interface = (int *)(pachet_coada + sizeof(uint32_t));
			size_t *target_len = (size_t *)(pachet_coada + sizeof(uint32_t) + sizeof(int));
			char *target_buf = pachet_coada + sizeof(uint32_t) + sizeof(int) + sizeof(size_t);

			*target_ip = best_route->next_hop;
			*target_interface = best_route->interface;
			*target_len = len;
			memcpy(target_buf, buf, len);

			queue_enq(coada_de_pachete, pachet_coada);
				
			send_arp_request(best_route->next_hop, best_route->interface);
		}
	}
	return 0;
}

