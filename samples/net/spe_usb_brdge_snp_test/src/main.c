// /* Networking DHCPv4 client */

// /*
//  * Copyright (c) 2017 ARM Ltd.
//  * Copyright (c) 2016 Intel Corporation.
//  *
//  * SPDX-License-Identifier: Apache-2.0
//  */

// #include <zephyr/logging/log.h>
// LOG_MODULE_REGISTER(net_dhcpv4_client_sample, LOG_LEVEL_DBG);

// #include <zephyr/kernel.h>
// #include <zephyr/linker/sections.h>
// #include <errno.h>
// #include <stdio.h>

// #include <zephyr/net/net_if.h>
// #include <zephyr/net/net_core.h>
// #include <zephyr/net/net_context.h>
// #include <zephyr/net/net_mgmt.h>

// #define DHCP_OPTION_NTP (42)

// static uint8_t ntp_server[4];

// static struct net_mgmt_event_callback mgmt_cb;

// static struct net_dhcpv4_option_callback dhcp_cb;

// static void start_dhcpv4_client(struct net_if *iface, void *user_data)
// {
// 	ARG_UNUSED(user_data);

// 	LOG_INF("Start on %s: index=%d", net_if_get_device(iface)->name,
// 		net_if_get_by_iface(iface));
// 	net_dhcpv4_start(iface);
// }

// static void handler(struct net_mgmt_event_callback *cb,
// 		    uint32_t mgmt_event,
// 		    struct net_if *iface)
// {
// 	int i = 0;

// 	if (mgmt_event != NET_EVENT_IPV4_ADDR_ADD) {
// 		return;
// 	}

// 	for (i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
// 		char buf[NET_IPV4_ADDR_LEN];

// 		if (iface->config.ip.ipv4->unicast[i].ipv4.addr_type !=
// 							NET_ADDR_DHCP) {
// 			continue;
// 		}

// 		LOG_INF("   Address[%d]: %s", net_if_get_by_iface(iface),
// 			net_addr_ntop(AF_INET,
// 			    &iface->config.ip.ipv4->unicast[i].ipv4.address.in_addr,
// 						  buf, sizeof(buf)));
// 		LOG_INF("    Subnet[%d]: %s", net_if_get_by_iface(iface),
// 			net_addr_ntop(AF_INET,
// 				       &iface->config.ip.ipv4->unicast[i].netmask,
// 				       buf, sizeof(buf)));
// 		LOG_INF("    Router[%d]: %s", net_if_get_by_iface(iface),
// 			net_addr_ntop(AF_INET,
// 						 &iface->config.ip.ipv4->gw,
// 						 buf, sizeof(buf)));
// 		LOG_INF("Lease time[%d]: %u seconds", net_if_get_by_iface(iface),
// 			iface->config.dhcpv4.lease_time);
// 	}
// }

// static void option_handler(struct net_dhcpv4_option_callback *cb,
// 			   size_t length,
// 			   enum net_dhcpv4_msg_type msg_type,
// 			   struct net_if *iface)
// {
// 	char buf[NET_IPV4_ADDR_LEN];

// 	LOG_INF("DHCP Option %d: %s", cb->option,
// 		net_addr_ntop(AF_INET, cb->data, buf, sizeof(buf)));
// }

// int main(void)
// {
// 	LOG_INF("Run dhcpv4 client");

// 	net_mgmt_init_event_callback(&mgmt_cb, handler,
// 				     NET_EVENT_IPV4_ADDR_ADD);
// 	net_mgmt_add_event_callback(&mgmt_cb);

// 	net_dhcpv4_init_option_callback(&dhcp_cb, option_handler,
// 					DHCP_OPTION_NTP, ntp_server,
// 					sizeof(ntp_server));

// 	net_dhcpv4_add_option_callback(&dhcp_cb);

// 	net_if_foreach(start_dhcpv4_client, NULL);
// 	return 0;
// }


#include <zephyr.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_context.h>
#include <zephyr/usb/usb_device.h>

static struct net_if *usb_iface;
static struct net_if *lan_iface;

void forward_packet(struct net_pkt *pkt, struct net_if *dest_iface) {
    if (!pkt || !dest_iface) {
        printk("Invalid packet or interface\n");
        return;
    }

    net_pkt_ref(pkt);
    if (net_recv_data(dest_iface, pkt) < 0) {
        printk("Failed to forward packet\n");
        net_pkt_unref(pkt);
    } else {
        printk("Packet forwarded successfully\n");
    }
}

void usbnet_rx_handler(struct net_if *iface, struct net_pkt *pkt) {
    printk("Packet received on USBNet\n");
    forward_packet(pkt, lan_iface);
}

void lan865x_rx_handler(struct net_if *iface, struct net_pkt *pkt) {
    printk("Packet received on LAN865x\n");
    forward_packet(pkt, usb_iface);
}

void init_usbnet(struct net_if *usb_iface) {
    int ret = usb_enable(NULL);
    if (ret) {
        printk("USB initialization failed\n");
        return;
    }

    net_if_up(usb_iface);
    printk("USBNet interface is up\n");
}

void init_lan865x(struct net_if *lan_iface) {
    net_if_up(lan_iface);
    printk("LAN865x interface is up\n");
}

void start_dhcp_clients() {
    net_dhcpv4_start(usb_iface);
    net_dhcpv4_start(lan_iface);
}

void main(void) {
    printk("Starting Unified USBNet and LAN865x driver\n");

    usb_iface = net_if_get_by_name("USB");
    lan_iface = net_if_get_default();

    if (!usb_iface || !lan_iface) {
        printk("Failed to initialize interfaces\n");
        return;
    }

    init_usbnet(usb_iface);
    init_lan865x(lan_iface);

    net_if_set_rx_handler(usb_iface, usbnet_rx_handler, NULL);
    net_if_set_rx_handler(lan_iface, lan865x_rx_handler, NULL);

    start_dhcp_clients();

    printk("Unified driver initialized successfully\n");
}

