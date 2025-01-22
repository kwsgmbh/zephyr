/*
 * Ethernet over USB device
 *
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(usb_net, 4);

#include <zephyr/init.h>

#include <zephyr/net/ethernet.h>
#include <net_private.h>

#include <usb_device.h>
#include <usb_descriptor.h>

#include "netusb.h"
#include <eth_forward_reciv.h>
//#include <bridged_iface_utils.h>
#include <print_packet.h>
#include <arp.h>
#define CONFIG_TARGET_ETH_IFACE_INDEX 2
static bool promiscuous_mode_enabled = false;

static int process_arp_packet(struct net_pkt *pkt_clone, struct net_if *eth_iface, bool has_eth_header);
static int handle_and_forward_arp(struct net_pkt *pkt_clone, struct net_if *eth_iface);
static struct __netusb {
	struct net_if *iface;
	const struct netusb_function *func;
} netusb;

static struct net_if *eth_iface = NULL;


// void handle_arp_packet(struct net_pkt *pkt, struct net_if *eth_iface)
// {
//     // Clone the packet
//     struct net_pkt *pkt_copy = net_pkt_clone(pkt, K_NO_WAIT);
//     if (!pkt_copy) {
//         LOG_ERR("Failed to clone the packet");
//         return;
//     }

//     // Initialize cursor for the cloned packet
//     net_pkt_cursor_init(pkt_copy);

//     // Skip the Ethernet header to access ARP
//     if (net_pkt_skip(pkt_copy, sizeof(struct net_eth_hdr)) != 0) {
//         LOG_ERR("Failed to skip Ethernet header");
//         net_pkt_unref(pkt_copy);
//         return;
//     }

//     // Read and parse ARP header
//     struct net_arp_hdr arp_hdr;
//     if (net_pkt_read(pkt_copy, &arp_hdr, sizeof(struct net_arp_hdr)) != 0) {
//         LOG_ERR("Failed to read ARP header");
//         net_pkt_unref(pkt_copy);
//         return;
//     }

//     // Modify ARP fields if needed
//     if (arp_hdr.opcode == htons(NET_ARP_REQUEST) ||
//         arp_hdr.opcode == htons(NET_ARP_REPLY)) {
//         LOG_INF("Handling ARP packet");

//         // Modify the source protocol address (e.g., gateway IP)
//         uint8_t new_gateway[4] = {192, 168, 2, 254}; // Example gateway address
//         memcpy(arp_hdr.src_proto_addr, new_gateway, sizeof(arp_hdr.src_proto_addr));
//         LOG_INF("Updated ARP gateway to %d.%d.%d.%d",
//                 new_gateway[0], new_gateway[1], new_gateway[2], new_gateway[3]);
//     }

//     // Write the modified ARP header back to the packet
//     net_pkt_cursor_init(pkt_copy);
//     if (net_pkt_skip(pkt_copy, sizeof(struct net_eth_hdr)) != 0 ||
//         net_pkt_write(pkt_copy, &arp_hdr, sizeof(struct net_arp_hdr)) != 0) {
//         LOG_ERR("Failed to update ARP header in the packet");
//         net_pkt_unref(pkt_copy);
//         return;
//     }

//     // Forward the modified packet to the Ethernet interface
//     if (net_recv_data(eth_iface, pkt_copy) < 0) {
//         LOG_ERR("Failed to forward the packet");
//         net_pkt_unref(pkt_copy);
//     } else {
//         LOG_INF("Packet forwarded successfully");
//     }
// }

static int forward_packet_to_eth(struct net_pkt *pkt )
{
	LOG_INF(" -> forwarding");

    if (!pkt || !eth_iface) {
        LOG_INF("Invalid packet or target interface");
        return -EINVAL;
    }

	LOG_INF(" -> checked IFace");

    // Clone the packet for forwarding
    struct net_pkt *pkt_clone = net_pkt_clone(pkt, K_NO_WAIT);
    if (!pkt_clone) {
        LOG_INF("Failed to clone packet for forwarding");
        return -ENOMEM;
    }

	LOG_INF(" -> cloned packet ");

	struct net_eth_hdr eth_hdr;
    bool has_eth_header = true;

    if (net_pkt_read(pkt_clone, &eth_hdr, sizeof(struct net_eth_hdr)) != 0) {
        LOG_WRN("No Ethernet header found, assuming raw packet");
        has_eth_header = false;
    }


	if (has_eth_header) {
	uint16_t eth_type = ntohs(eth_hdr.type);

    // Skip the Ethernet header to access ARP
    if (net_pkt_skip(pkt_clone, sizeof(struct net_eth_hdr)) != 0) {
        LOG_ERR("Failed to skip Ethernet header");
        net_pkt_unref(pkt_clone);
        return 0 ;
    }
	if (eth_type == NET_ETH_PTYPE_ARP) {
    LOG_INF("ARP packet detected");
    struct net_arp_hdr arp_hdr;

    // Read the ARP header from the cloned packet
    if (net_pkt_read(pkt_clone, &arp_hdr, sizeof(struct net_arp_hdr)) == 0) {
        char src_ip[NET_IPV4_ADDR_LEN];
        char dst_ip[NET_IPV4_ADDR_LEN];
        net_addr_ntop(AF_INET, &arp_hdr.src_ipaddr, src_ip, sizeof(src_ip));
        net_addr_ntop(AF_INET, &arp_hdr.dst_ipaddr, dst_ip, sizeof(dst_ip));

        LOG_INF("ARP src IP: %s", src_ip);
        LOG_INF("ARP dst IP: %s", dst_ip);

        // Update the source protocol address (src_ipaddr)
        uint8_t new_gateway[NET_IPV4_ADDR_SIZE] = {192, 168, 2, 244}; // Replace with dynamic gateway if needed
        memcpy(arp_hdr.src_ipaddr, new_gateway, sizeof(arp_hdr.src_ipaddr));

        // Write the updated ARP header back to the packet
        net_pkt_cursor_init(pkt_clone);
        if (net_pkt_skip(pkt_clone, sizeof(struct net_eth_hdr)) == 0) { // Skip Ethernet header
            if (net_pkt_write(pkt_clone, &arp_hdr, sizeof(struct net_arp_hdr)) == 0) {
                LOG_INF("Updated ARP src IP to new gateway: %d.%d.%d.%d",
                        new_gateway[0], new_gateway[1], new_gateway[2], new_gateway[3]);
            } else {
                LOG_ERR("Failed to write updated ARP header to packet");
            }
        } else {
            LOG_ERR("Failed to reset cursor to ARP header position");
        }
    } else {
        LOG_ERR("Failed to read ARP header");
    }
 } else if (eth_type == NET_ETH_PTYPE_IP) {
            LOG_INF("IPv4 packet detected");
            struct net_ipv4_hdr ipv4_hdr;

            if (net_pkt_read(pkt_clone, &ipv4_hdr, sizeof(struct net_ipv4_hdr)) == 0) {
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

	int ret = net_recv_data(eth_iface, pkt_clone);

	LOG_INF(" -> ret_recv_data returned %d ", ret);
    // Pass the cloned packet to the Ethernet interface
    if ( ret < 0) {
        LOG_INF("Failed to forward packet to Ethernet interface");
        net_pkt_unref(pkt_clone);
        return -EIO;
    }

	LOG_INF(" -> sent packet packet ");
	net_pkt_unref(pkt_clone);
	return 0;
    
 }else {
        // Handle raw packet without Ethernet header
        LOG_INF("Checking for ARP packet without Ethernet header");

        struct net_arp_hdr arp_hdr;
        
        LOG_HEXDUMP_INF(net_pkt_data(pkt_clone), net_pkt_get_len(pkt_clone), "Packet data dump");

        // Ensure packet cursor is positioned at the beginning
        net_pkt_cursor_init(pkt_clone);

        // Check if the packet length is sufficient for an ARP header
        if (net_pkt_remaining_data(pkt_clone) < sizeof(struct net_arp_hdr)) {
            LOG_ERR("Packet too short for ARP header");
            net_pkt_unref(pkt_clone);
            return -EINVAL;
        }

        if (net_pkt_read(pkt_clone, &arp_hdr, sizeof(struct net_arp_hdr)) == 0) {
            char src_ip[NET_IPV4_ADDR_LEN];
            char dst_ip[NET_IPV4_ADDR_LEN];
            net_addr_ntop(AF_INET, &arp_hdr.src_ipaddr, src_ip, sizeof(src_ip));
            net_addr_ntop(AF_INET, &arp_hdr.dst_ipaddr, dst_ip, sizeof(dst_ip));

            LOG_INF("ARP src IP: %s", src_ip);
            LOG_INF("ARP dst IP: %s", dst_ip);

            // Update the source protocol address (src_ipaddr)
            uint8_t new_gateway[NET_IPV4_ADDR_SIZE] = {192, 168, 2, 244}; // Replace with dynamic gateway if needed
            memcpy(arp_hdr.src_ipaddr, new_gateway, sizeof(arp_hdr.src_ipaddr));

            // Reset cursor and write updated ARP header back to the packet
            net_pkt_cursor_init(pkt_clone);
            if (net_pkt_write(pkt_clone, &arp_hdr, sizeof(struct net_arp_hdr)) == 0) {
                LOG_INF("Updated ARP src IP to new gateway: %d.%d.%d.%d",
                        new_gateway[0], new_gateway[1], new_gateway[2], new_gateway[3]);
            } else {
                LOG_ERR("Failed to write updated ARP header");
            }
        } else {
            LOG_ERR("Failed to read ARP header");
        }

        int ret = net_recv_data(eth_iface, pkt_clone);

        LOG_INF(" -> ret_recv_data returned %d ", ret);
        // Pass the cloned packet to the Ethernet interface
        if ( ret < 0) {
            LOG_INF("Failed to forward packet to Ethernet interface");
            net_pkt_unref(pkt_clone);
        return -EIO;
        }

	    LOG_INF(" -> sent packet packet ");
	    //net_pkt_unref(pkt_clone);
	    return 0;
    }

 }

static int handle_and_forward_arp(struct net_pkt *pkt_clone, struct net_if *eth_iface) {
    struct net_eth_hdr eth_hdr;
    bool has_eth_header = true;

    // Check for Ethernet header
    if (net_pkt_read(pkt_clone, &eth_hdr, sizeof(struct net_eth_hdr)) != 0) {
        LOG_WRN("No Ethernet header found, assuming raw packet");
        has_eth_header = false;
    }

    if (has_eth_header) {
        uint16_t eth_type = ntohs(eth_hdr.type);

        // Skip the Ethernet header to access ARP
        if (net_pkt_skip(pkt_clone, sizeof(struct net_eth_hdr)) != 0) {
            LOG_ERR("Failed to skip Ethernet header");
            net_pkt_unref(pkt_clone);
            return -EINVAL;
        }

        if (eth_type == NET_ETH_PTYPE_ARP) {
            LOG_INF("ARP packet detected with Ethernet header");
            return process_arp_packet(pkt_clone, eth_iface, true);
        }
    } else {
        LOG_INF("Checking for ARP packet without Ethernet header");
        return process_arp_packet(pkt_clone, eth_iface, false);
    }

    LOG_INF("Non-ARP packet, dropping");
    net_pkt_unref(pkt_clone);
    return -EINVAL;
}

static int process_arp_packet(struct net_pkt *pkt_clone, struct net_if *eth_iface, bool has_eth_header) {
    struct net_arp_hdr arp_hdr;

    // Read the ARP header
    if (net_pkt_read(pkt_clone, &arp_hdr, sizeof(struct net_arp_hdr)) != 0) {
        LOG_ERR("process_arp_packet : Failed to read ARP header");
        net_pkt_unref(pkt_clone);
        return -EINVAL;
    }

    char src_ip[NET_IPV4_ADDR_LEN];
    char dst_ip[NET_IPV4_ADDR_LEN];
    net_addr_ntop(AF_INET, &arp_hdr.src_ipaddr, src_ip, sizeof(src_ip));
    net_addr_ntop(AF_INET, &arp_hdr.dst_ipaddr, dst_ip, sizeof(dst_ip));

    LOG_INF("ARP src IP: %s", src_ip);
    LOG_INF("ARP dst IP: %s", dst_ip);

    // Update the source protocol address (SPA)
    uint8_t new_gateway[NET_IPV4_ADDR_SIZE] = {192, 168, 2, 244}; // Example gateway
    memcpy(arp_hdr.src_ipaddr, new_gateway, sizeof(arp_hdr.src_ipaddr));

    // Reset the packet cursor to write back the ARP header
    net_pkt_cursor_init(pkt_clone);
    if (has_eth_header) {
        if (net_pkt_skip(pkt_clone, sizeof(struct net_eth_hdr)) != 0) {
            LOG_ERR("Failed to reset cursor after Ethernet header");
            net_pkt_unref(pkt_clone);
            return -EINVAL;
        }
    }

    // Write the updated ARP header back to the packet
    if (net_pkt_write(pkt_clone, &arp_hdr, sizeof(struct net_arp_hdr)) != 0) {
        LOG_ERR("Failed to write updated ARP header to packet");
        net_pkt_unref(pkt_clone);
        return -EINVAL;
    }

    LOG_INF("Updated ARP src IP to new gateway: %d.%d.%d.%d",
            new_gateway[0], new_gateway[1], new_gateway[2], new_gateway[3]);

    // Forward the packet to the Ethernet interface
    int ret = net_recv_data(eth_iface, pkt_clone);
    if (ret < 0) {
        LOG_ERR("Failed to forward packet to Ethernet interface");
        net_pkt_unref(pkt_clone);
        return -EIO;
    }

    LOG_INF("Successfully forwarded ARP packet to Ethernet interface");
    net_pkt_unref(pkt_clone);
    return 0;
}

static int netusb_send(const struct device *dev, struct net_pkt *pkt)
{
	int ret;

	ARG_UNUSED(dev);

	//LOG_DBG("Send pkt, len %zu", net_pkt_get_len(pkt));
	LOG_INF("....netusb_send....");

    //LOG_HEXDUMP_INF(net_pkt_data(pkt), net_pkt_get_len(pkt), "Packet data dump");

	//display_net_pkt_details(pkt);
	

	if (!netusb_enabled()) {
		LOG_ERR("interface disabled");
		return -ENODEV;
	}

	ret = netusb.func->send_pkt(pkt);
	if (ret) {
		return ret;
		
	}

	return 0;
}

struct net_if *netusb_net_iface(void)
{
	return netusb.iface;

}

void netusb_recv(struct net_pkt *pkt)
{
	//LOG_DBG("Recv pkt, len %zu", net_pkt_get_len(pkt));
	//LOG_INF("....USB RECEIVE....");
	//display_net_pkt_details(pkt);
    //LOG_HEXDUMP_INF(net_pkt_data(pkt), net_pkt_get_len(pkt), "Packet data dump");

	if (net_recv_data(netusb.iface, pkt) < 0) {
		LOG_ERR("Packet %p dropped by NET stack", pkt);
		net_pkt_unref(pkt);
	}

	// if (forward_packet_receive(pkt) < 0) {
	// 	LOG_INF("Packet %p dropped by NET stack", pkt);
	// 	net_pkt_unref(pkt);
	// }
	

	// if (forward_packet_to_eth(pkt) < 0) {
    //     LOG_ERR("Failed to forward packet");
		
    // }
	

	// struct net_pkt *pkt_clone = net_pkt_clone(pkt, K_NO_WAIT);
    // if (!pkt_clone) {
    //     LOG_ERR("Failed to clone packet");
    //     return -ENOMEM;
    // }

    // int ret = handle_and_forward_arp(pkt_clone, eth_iface);
    // if (ret == 0) {
    //     LOG_INF("Packet processed and forwarded");
    // } else {
    //     LOG_INF("Packet processing failed with error: %d", ret);
    // }

	//net_pkt_unref(pkt);
}

/*code for forwading packets to ethernet */  

// void netusb_recv(struct net_pkt *pkt)
// {
//     LOG_DBG("Received packet, len %zu", net_pkt_get_len(pkt));

//     if (!pkt || !eth_iface) {
//         LOG_ERR("Invalid packet or target interface");
//         net_pkt_unref(pkt);
//         return;
//     }

//     // Forward the packet to the Ethernet interface
//     if (net_recv_data(eth_iface, pkt) < 0) {
//         LOG_ERR("Packet %p dropped by NET stack", pkt);
//         net_pkt_unref(pkt);
//     } else {
//         LOG_DBG("Packet forwarded to Ethernet interface");
//     }
// }


// Initialization function to set up the target Ethernet interface
static int setup_eth_interface(void)
{
    eth_iface = net_if_get_by_index(CONFIG_TARGET_ETH_IFACE_INDEX);
    if (!eth_iface) {
        LOG_ERR("Failed to get target Ethernet interface");
        return -ENODEV;
    }

    LOG_INF("Target Ethernet interface initialized: %p", eth_iface);
    return 0;
}


static int netusb_connect_media(void)
{
	LOG_DBG("");

	if (!netusb_enabled()) {
		LOG_ERR("interface disabled");
		return -ENODEV;
	}

	if (!netusb.func->connect_media) {
		return -ENOTSUP;
	}

	return netusb.func->connect_media(true);
}

static int netusb_disconnect_media(void)
{
	LOG_DBG("");

	if (!netusb_enabled()) {
		LOG_ERR("interface disabled");
		return -ENODEV;
	}

	if (!netusb.func->connect_media) {
		return -ENOTSUP;
	}

	return netusb.func->connect_media(false);
}

void netusb_enable(const struct netusb_function *func)
{
	LOG_DBG("");

	netusb.func = func;

	net_if_carrier_on(netusb.iface);
	netusb_connect_media();
}

void netusb_disable(void)
{
	LOG_DBG("");

	if (!netusb_enabled()) {
		return;
	}

	netusb.func = NULL;

	netusb_disconnect_media();
	net_if_carrier_off(netusb.iface);
}

bool netusb_enabled(void)
{
	return !!netusb.func;
}

static void netusb_init(struct net_if *iface)
{
	static uint8_t mac[6] = { 0x00, 0x00, 0x5E, 0x00, 0x53, 0x00 };

	LOG_DBG("netusb device initialization");

	netusb.iface = iface;

	ethernet_init(iface);
	net_if_carrier_off(iface);

	net_if_set_link_addr(iface, mac, sizeof(mac), NET_LINK_ETHERNET);

	if (setup_eth_interface() < 0) {
        LOG_ERR("Failed to set up Ethernet forwarding interface");
    }


	LOG_INF("netusb initialized");
}

static int netusb_set_promiscuous_mode(const struct device *dev,
                                       enum ethernet_config_type type,
                                       const struct ethernet_config *config)
{
    // Check if the configuration type is for promiscuous mode
    if (type != ETHERNET_CONFIG_TYPE_PROMISC_MODE) {
        return -EINVAL; // Return an error for unsupported types
    }

    // Extract the promiscuous mode value from the config
    bool enable = config->promisc_mode;

    if (enable) {
        LOG_INF("Enabling promiscuous mode");
        // Add logic to enable promiscuous mode
        // alredy forwads all the packets
    } else {
        LOG_INF("Disabling promiscuous mode");
        // Add logic to disable promiscuous mode
    }

    return 0; // Indicate success
}


static enum ethernet_hw_caps netusb_get_capabilities(const struct device *dev)
{
    return ETHERNET_PROMISC_MODE; // Advertise promiscuous mode capability
}


static const struct ethernet_api netusb_api_funcs = {
	.iface_api.init = netusb_init,
	.get_capabilities = netusb_get_capabilities,
    .set_config = netusb_set_promiscuous_mode,
	.send = netusb_send,
    
};

static int netusb_init_dev(const struct device *dev)
{
	ARG_UNUSED(dev);
	return 0;
}


NET_DEVICE_INIT(eth_netusb, "eth_netusb", netusb_init_dev, NULL, NULL, NULL,
		CONFIG_ETH_INIT_PRIORITY, &netusb_api_funcs, ETHERNET_L2,
		NET_L2_GET_CTX_TYPE(ETHERNET_L2), NET_ETH_MTU);


/*


int net_recv_data(struct net_if *iface, struct net_pkt *pkt);

/**
 * @brief Send data to network.
 *
 * @details Send data to network. This should not be used normally by
 * applications as it requires that the network packet is properly
 * constructed.
 *
 * @param pkt Network packet.
 *
 * @return 0 if ok, <0 if error. If <0 is returned, then the caller needs
 * to unref the pkt in order to avoid memory leak.





*/