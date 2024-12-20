/* Networking DHCPv4 client */

/*
 * Copyright (c) 2017 ARM Ltd.
 * Copyright (c) 2016 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(pico_spe_custom_debug, LOG_LEVEL_DBG);
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>

#include <zephyr/linker/sections.h>
#include <errno.h>
#include <stdio.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_config.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/dhcpv4_server.h> 
// #include <zephyr/subsys/net/ip/route.h>
#include "netusb.h"
#include "ethernet.h"
#include "ethernet_bridge.h"
#include "route.h"

// #include <zephyr/subsys/net/l2/ethernet/bridge.h>
#define SLEEP_TIME_MS   1000
#define LED0_NODE DT_ALIAS(led0)
#define DHCP_OPTION_NTP (42)
#define LED_PIN 25
static uint8_t ntp_server[4];

static struct net_mgmt_event_callback mgmt_cb;

static struct net_dhcpv4_option_callback dhcp_cb;

static struct net_if *eth_iface;
static struct net_if *usb_iface;

static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);

void toggle_led(void)
{
    int ret;
	bool led_state = true;

	if (!gpio_is_ready_dt(&led)) {
		return 0;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return 0;
	}

	while (1) {
		ret = gpio_pin_toggle_dt(&led);
		if (ret < 0) {
			return 0;
		}

		led_state = !led_state;
		printf("LED state: %s\n", led_state ? "ON" : "OFF");
		k_msleep(SLEEP_TIME_MS);
	}
}

int netusb_send( const struct device *dev, struct net_pkt *pkt);



static int my_connect_media(bool status)
{
    LOG_INF("Media connection status: %s", status ? "connected" : "disconnected");
    return 0;
}

static int my_send_pkt(struct net_pkt *pkt)
{
    LOG_INF("Sending packet, length: %zu", net_pkt_get_len(pkt));
    return 0;
}

static const struct netusb_function my_netusb_function = {
    .connect_media = my_connect_media,
    .send_pkt = my_send_pkt,
};

static void start_dhcpv4_client(struct net_if *iface, void *user_data)
{
	ARG_UNUSED(user_data);

	LOG_INF("Start on %s: index=%d", net_if_get_device(iface)->name,
		net_if_get_by_iface(iface));
	net_dhcpv4_start(iface);
}

static void start_dhcpv4_server(struct net_if *iface)
{
    int ret;
    struct in_addr base_addr;
    LOG_INF("entered into start server function\n");
    if (net_addr_pton(AF_INET, "192.168.1.4", &base_addr) < 0) {
        LOG_ERR("Invalid base address for DHCP server");
        return;
    }

    LOG_INF("Start DHCP server on %s: index=%d", net_if_get_device(iface)->name,
            net_if_get_by_iface(iface));

    ret = net_dhcpv4_server_start(iface, &base_addr);
    if (ret != 0) {
        LOG_ERR("Failed to start DHCP server: %d", ret);
    }
}

static void assign_static_ip(struct net_if *iface, const char *ip, const char *netmask, const char *gateway)
{
    struct in_addr addr, netmask_addr, gateway_addr;

    // LOG_INF("Assigning static IP %s to %s", ip, net_if_get_device(iface)->name);

    if (net_addr_pton(AF_INET, ip, &addr) < 0 ||
        net_addr_pton(AF_INET, netmask, &netmask_addr) < 0 ||
        net_addr_pton(AF_INET, gateway, &gateway_addr) < 0) {
        LOG_ERR("Invalid static IP configuration");
        return;
    }

    net_if_ipv4_addr_add(iface, &addr, NET_ADDR_MANUAL, 0);
    net_if_ipv4_set_netmask(iface, &netmask_addr);
    net_if_ipv4_set_gw(iface, &gateway_addr);
}


static void assign_ipv6_addresses(void) {
    struct net_if *eth_iface = net_if_get_by_index(1); // LAN interface
    struct net_if *usb_iface = net_if_get_by_index(2); // USB interface
    struct in6_addr addr;

    // Enable NDP (Neighbor Discovery Protocol) for IPv6
    // net_config_set(NET_IPV6_ND, true);

    // Assign IPv6 address to eth0 (LAN)
    if (eth_iface) {
        net_ipv6_addr_create(&addr, 0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 1);
        net_if_ipv6_addr_add(eth_iface, &addr, NET_ADDR_MANUAL, 0);
        LOG_INF("Assigned IPv6 2001:db8:1::1 to eth0");

        // Add a route through the USB interface as the gateway
        struct in6_addr nexthop;
        net_ipv6_addr_create(&nexthop, 0x2001, 0xdb8, 0x2, 0, 0, 0, 0, 1); // IP of the USB interface
        net_route_add(eth_iface, &addr, 64, &nexthop, 3600, 255); // Lifetime 3600 sec, max preference
        LOG_INF("Added IPv6 route 2001:db8:1::/64 via eth1");
    }

    // Assign IPv6 address to eth1 (USB)
    if (usb_iface) {
        net_ipv6_addr_create(&addr, 0x2001, 0xdb8, 0x2, 0, 0, 0, 0, 1);
        net_if_ipv6_addr_add(usb_iface, &addr, NET_ADDR_MANUAL, 0);
        LOG_INF("Assigned IPv6 2001:db8:2::1 to eth1");

        // Add a route to the LAN interface as the gateway
        struct in6_addr nexthop;
        net_ipv6_addr_create(&nexthop, 0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 1); // IP of the LAN interface
        net_route_add(usb_iface, &addr, 64, &nexthop, 3600, 255);
        LOG_INF("Added IPv6 route 2001:db8:2::/64 via eth0");
    }
}



static void handler(struct net_mgmt_event_callback *cb,
		    uint32_t mgmt_event,
		    struct net_if *iface)
{
	int i = 0;

	if (mgmt_event != NET_EVENT_IPV4_ADDR_ADD) {
		return;
	}

	for (i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
		char buf[NET_IPV4_ADDR_LEN];

		if (iface->config.ip.ipv4->unicast[i].ipv4.addr_type !=
							NET_ADDR_DHCP) {
			continue;
		}

		LOG_INF("   Address[%d]: %s", net_if_get_by_iface(iface),
			net_addr_ntop(AF_INET,
			    &iface->config.ip.ipv4->unicast[i].ipv4.address.in_addr,
						  buf, sizeof(buf)));
		LOG_INF("    Subnet[%d]: %s", net_if_get_by_iface(iface),
			net_addr_ntop(AF_INET,
				       &iface->config.ip.ipv4->unicast[i].netmask,
				       buf, sizeof(buf)));
		LOG_INF("    Router[%d]: %s", net_if_get_by_iface(iface),
			net_addr_ntop(AF_INET,
						 &iface->config.ip.ipv4->gw,
						 buf, sizeof(buf)));
		LOG_INF("Lease time[%d]: %u seconds", net_if_get_by_iface(iface),
			iface->config.dhcpv4.lease_time);
	}
}

static void option_handler(struct net_dhcpv4_option_callback *cb,
			   size_t length,
			   enum net_dhcpv4_msg_type msg_type,
			   struct net_if *iface)
{
	char buf[NET_IPV4_ADDR_LEN];

	LOG_INF("DHCP Option %d: %s", cb->option,
		net_addr_ntop(AF_INET, cb->data, buf, sizeof(buf)));
}

int init_usb(void)
{
    int ret;
    k_msleep(5000);
    ret = usb_enable(NULL);
    if (ret != 0) {
        LOG_ERR("USB enable error %d", ret);
        return ret;
    }

    return 0;
}

// static void setup_routes(void) {
//     struct in_addr dest, netmask, gateway;

//     // Route for Ethernet interface
//     net_addr_pton(AF_INET, "192.168.1.0", &dest);
//     net_addr_pton(AF_INET, "255.255.255.0", &netmask);
//     net_addr_pton(AF_INET, "192.168.1.254", &gateway); // Gateway for Ethernet
//     net_route_add(eth_iface, &dest, &netmask, &gateway);

//     // Route for USB interface
//     net_addr_pton(AF_INET, "192.168.2.0", &dest);
//     net_addr_pton(AF_INET, "255.255.255.0", &netmask);
//     net_addr_pton(AF_INET, "192.168.2.1", &gateway); // Gateway for USB
//     net_route_add(usb_iface, &dest, &netmask, &gateway);

//     LOG_INF("Static routes configured");
// }


// / Ethernet packet handler /
static void eth_recv_cb(struct net_if *iface, struct net_pkt *pkt)
{
    LOG_INF("Packet received on Ethernet");

    // Forward the packet to the USB interface
    netusb_recv(pkt);
}

static void usb_recv_cb(struct net_if *iface, struct net_pkt *pkt)
{
    LOG_INF("Packet received on USB");

    // Forward the packet to the LAN Ethernet interface
    if (net_recv_data(eth_iface, pkt) < 0) {
        LOG_ERR("Failed to forward packet from USB to Ethernet");
        net_pkt_unref(pkt);
    } else {
        LOG_INF("Packet forwarded from USB to Ethernet successfully");
    }
}


static void simulate_packet_reception(struct net_if *src_iface, struct net_if *dest_iface)
{
    struct net_pkt *pkt = net_pkt_alloc_with_buffer(src_iface, 128, AF_INET, IPPROTO_UDP, K_NO_WAIT);
    if (!pkt) {
        LOG_ERR("Failed to allocate packet");
        return;
    }
	LOG_DBG("****%d*****\n",src_iface);
    LOG_DBG("****%d*****\n",dest_iface);
    // Add dummy data to packet
    uint8_t *data = net_pkt_data(pkt);
    for (int i = 0; i < 128; i++) {
        data[i] = i % 256;
		// LOG_DBG("****%d*****",i);
    }

    // Set packet length (replace net_pkt_set_len if unavailable)
    // if (net_pkt_set_data(pkt, 128) < 0) {
    //     LOG_ERR("Failed to set packet data length");
    //     net_pkt_unref(pkt);
    //     return;
    // }
    eth_iface= net_if_get_by_index(1); // LAN interface
    usb_iface = net_if_get_by_index(2);
    // // Simulate reception
    if (src_iface == eth_iface) {
        eth_recv_cb(src_iface, pkt);
    } else if (src_iface == usb_iface) {
        usb_recv_cb(src_iface, pkt);
    }

    // // Free packet
    // net_pkt_unref(pkt);
}


int main(void)
{
	// struct net_if *iface_bridge = net_if_get_by_index(1); // Bridge interface
    struct net_if *eth_iface= net_if_get_by_index(1); // LAN interface
    struct net_if *usb_iface = net_if_get_by_index(2); // USB interface

    // toggle_led();

    // LOG_INF("Run dhcpv4 client");

	net_mgmt_init_event_callback(&mgmt_cb, handler,
				     NET_EVENT_IPV4_ADDR_ADD);
	net_mgmt_add_event_callback(&mgmt_cb);

    // Initialize USB interface (for netusb)
    if (init_usb() != 0) {
        LOG_ERR("Failed to initialize USB");
        return -1;
    }
    

	net_dhcpv4_init_option_callback(&dhcp_cb, option_handler,
					DHCP_OPTION_NTP, ntp_server,
					sizeof(ntp_server));

	net_dhcpv4_add_option_callback(&dhcp_cb);
    
  
    netusb_enable(&my_netusb_function);

    // if (eth_iface) {
    //     assign_static_ip(eth_iface, "192.168.1.2", "255.255.255.0", "192.168.1.254");
    // } else {
    //     LOG_ERR("Failed to get LAN interface");
    // }

    // if (usb_iface) {
    //     assign_static_ip(usb_iface, "192.168.1.3", "255.255.255.0", "192.168.1.254");
    // } else {
    //     LOG_ERR("Failed to get USB interface");
    // }
    // setup_routes();
    assign_ipv6_addresses();

	// simulate_packet_reception(eth_iface, usb_iface); // Test Ethernet to USB
    
    // start_dhcpv4_server(usb_iface);

    

	return 0;
}