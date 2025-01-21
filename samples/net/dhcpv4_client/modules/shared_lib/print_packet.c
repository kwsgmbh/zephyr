#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_pkt_debug, LOG_LEVEL_DBG);
#include <zephyr/net/net_core.h>
#include <zephyr/net/ethernet.h>
#include "net_private.h"
#include <arp.h>


// void display_net_pkt_details(struct net_pkt *pkt) {
//     struct net_pkt *pkt_copy = net_pkt_clone(pkt, K_NO_WAIT);
//     if (!pkt_copy) {
//         LOG_ERR("Failed to clone the packet");
//         return;
//     }

//     //Dump the cloned packet

//     // LOG_INF("Dumping net_pkt fragments:");
//     // net_pkt_hexdump(pkt_copy, "Fragmented packet contents");

//     //Initialize cursor for the cloned packet
//     net_pkt_cursor_init(pkt_copy);


//     //Skip the Ethernet header if present
//     if (IS_ENABLED(CONFIG_NET_L2_ETHERNET)) {
//         if (net_pkt_skip(pkt_copy, sizeof(struct net_eth_hdr)) != 0) {
//             LOG_ERR("Failed to skip Ethernet header");
//             net_pkt_unref(pkt_copy);
//             return;
//         }
//     }

//     //Read and print IPv4 header
//     struct net_ipv4_hdr ipv4_hdr;
//     if (net_pkt_read(pkt_copy, &ipv4_hdr, sizeof(ipv4_hdr)) == 0) {
//         char src[NET_IPV4_ADDR_LEN];
//         char dst[NET_IPV4_ADDR_LEN];
        
//         //Convert and print the source and destination ips
//         LOG_INF("IPv4 src: %s", net_addr_ntop(AF_INET, &ipv4_hdr.src, src, sizeof(src)));
//         LOG_INF("IPv4 dst: %s", net_addr_ntop(AF_INET, &ipv4_hdr.dst, dst, sizeof(dst)));
//     } else {
//         LOG_ERR("Failed to read IPv4 header from cloned packet");
//     }

//     //Release the cloned packel
//     net_pkt_unref(pkt_copy);
// }

void display_net_pkt_details(struct net_pkt *pkt) {
     struct net_pkt *pkt_copy = net_pkt_clone(pkt, K_NO_WAIT);
    if (!pkt_copy) {
        LOG_ERR("Failed to clone the packet");
        return;
    }

    // Initialize cursor for the cloned packet
    net_pkt_cursor_init(pkt_copy);

    // Try to read the Ethernet header

    /* struct net_eth_hdr {
        struct net_eth_addr dst;
        struct net_eth_addr src;
        uint16_t type;
        } __packed;
        

        struct net_ipv4_hdr {
	uint8_t vhl;
	uint8_t tos;
	uint16_t len;
	uint8_t id[2];
	uint8_t offset[2];
	uint8_t ttl;
	uint8_t proto;
	uint16_t chksum;
	uint8_t src[NET_IPV4_ADDR_SIZE];
	uint8_t dst[NET_IPV4_ADDR_SIZE];
} __packed;

The struct net_ipv4_hdr represents an IPv4 header. Here's a quick explanation of each field:

vhl: Combines the version (4 bits) and header length (4 bits).

Example: 0x45 means IPv4 with a header length of 5 (20 bytes).
tos: Type of Service (8 bits) for defining how the packet should be treated (e.g., priority).

len: Total length (16 bits) of the IPv4 packet (header + data).

id: Identification (16 bits) for fragmentation, used for reassembling fragmented packets.

offset: Fragmentation offset (16 bits), used in case the packet is fragmented.

ttl: Time to Live (8 bits), which limits the packet's lifetime in the network.

proto: Protocol (8 bits), specifying the upper layer protocol (e.g., TCP, UDP).

chksum: Header checksum (16 bits) for error-checking the header.

src: Source IP address (4 bytes).

dst: Destination IP address (4 bytes).
        
        
        
        */
   

    struct net_eth_hdr eth_hdr;
    bool has_eth_header = true;

    if (net_pkt_read(pkt_copy, &eth_hdr, sizeof(struct net_eth_hdr)) != 0) {
        LOG_WRN("No Ethernet header found, assuming raw packet");
        has_eth_header = false;
    }

    // Process based on the Ethernet header if it exists
    if (has_eth_header) {
        uint16_t eth_type = ntohs(eth_hdr.type);

        if (eth_type == NET_ETH_PTYPE_ARP) {
            LOG_INF("eth_header :ARP packet detected");
            struct net_arp_hdr arp_hdr;

            if (net_pkt_read(pkt_copy, &arp_hdr, sizeof(struct net_arp_hdr)) == 0) {
                char src_ip[NET_IPV4_ADDR_LEN];
                char dst_ip[NET_IPV4_ADDR_LEN];
                net_addr_ntop(AF_INET, &arp_hdr.src_ipaddr, src_ip, sizeof(src_ip));
                net_addr_ntop(AF_INET, &arp_hdr.dst_ipaddr, dst_ip, sizeof(dst_ip));

                LOG_INF("ARP src IP: %s", src_ip);
                LOG_INF("ARP dst IP: %s", dst_ip);
            } else {
                LOG_ERR("Failed to read ARP header");
            }
        } else if (eth_type == NET_ETH_PTYPE_IP) {
            LOG_INF("IPv4 packet detected");
            struct net_ipv4_hdr ipv4_hdr;

            if (net_pkt_read(pkt_copy, &ipv4_hdr, sizeof(struct net_ipv4_hdr)) == 0) {
                char src[NET_IPV4_ADDR_LEN];
                char dst[NET_IPV4_ADDR_LEN];
                net_addr_ntop(AF_INET, &ipv4_hdr.src, src, sizeof(src));
                net_addr_ntop(AF_INET, &ipv4_hdr.dst, dst, sizeof(dst));

                LOG_INF("IPv4 Header Details:");
                LOG_INF("  Version and Header Length: 0x%02X", ipv4_hdr.vhl);
                LOG_INF("  Type of Service: 0x%02X", ipv4_hdr.tos);
                LOG_INF("  Total Length: %d bytes", ntohs(*((uint16_t *)&ipv4_hdr.len)));
                LOG_INF("  Identification: 0x%02X%02X", ipv4_hdr.id[0], ipv4_hdr.id[1]);
                LOG_INF("  Fragment Offset: 0x%02X%02X", ipv4_hdr.offset[0], ipv4_hdr.offset[1]);
                LOG_INF("  Time to Live (TTL): %d", ipv4_hdr.ttl);
                LOG_INF("  Protocol: %d", ipv4_hdr.proto);
                LOG_INF("  Checksum: 0x%04X", ntohs(ipv4_hdr.chksum));
                LOG_INF("  Source IP: %s", src);
                LOG_INF("  Destination IP: %s", dst);
            } else {
                LOG_ERR("Failed to read IPv4 header");
            }
        } else {
            LOG_INF("Other Ethernet packet type: 0x%04X", eth_type);
        }
    } else {
        LOG_INF("Processing non-Ethernet packet");
        // Handle raw or non-Ethernet packets here as needed
        LOG_INF("IT IS A NON ETHERNET PACK");
    }

    // Release the cloned packet
    net_pkt_unref(pkt_copy);
}
