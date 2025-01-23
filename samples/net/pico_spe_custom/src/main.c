/* USB2Ethernet */

/*
 * Copyright (c) 2017 ARM Ltd.
 * Copyright (c) 2016 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Author : Aravind PV
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(pico_spe_custom_debug, LOG_LEVEL_DBG);
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>

#include <zephyr/linker/sections.h>
#include <errno.h>
#include <stdio.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_config.h>
#include <zephyr/net/dhcpv4_server.h> 
#include "route.h"
#include "nbr.h"
#include "ipv6.h"
#include "netusb.h"

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
void discover_and_add_neighbors(void);
void add_ipv6_routes(void);

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

void discover_and_add_neighbors(void)
{
    struct net_if *eth_iface = net_if_get_by_index(1); // eth_lan interface
    struct net_if *usb_iface = net_if_get_by_index(2); // usbnet interface

    struct in6_addr eth_neighbor_addr = { { { 0x20, 0x01, 0x0D, 0xB8, 0x02, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } };
    struct in6_addr usb_neighbor_addr = { { { 0x20, 0x01, 0x0D, 0xB8, 0x01, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } };

    if (eth_iface && usb_iface) {
        // Add usbnet as a neighbor to eth_lan
        if (!net_ipv6_nbr_add(eth_iface, &eth_neighbor_addr, NULL, false, NET_IPV6_NBR_STATE_REACHABLE)) {
            LOG_ERR("Failed to add neighbor 2001:db8:2::1 to eth_lan");
        } else {
            LOG_INF("Added neighbor 2001:db8:2::1 to eth_lan");
        }

        // Add eth_lan as a neighbor to usbnet
        if (!net_ipv6_nbr_add(usb_iface, &usb_neighbor_addr, NULL, false, NET_IPV6_NBR_STATE_REACHABLE)) {
            LOG_ERR("Failed to add neighbor 2001:db8:1::1 to usbnet");
        } else {
            LOG_INF("Added neighbor 2001:db8:1::1 to usbnet");
        }

    } else {
        LOG_ERR("Interfaces not found, cannot add neighbors");
    }
    
}

void add_ipv6_routes(void)
{
    struct net_if *eth_iface = net_if_get_by_index(1); 
    struct net_if *usb_iface = net_if_get_by_index(2);
    
    if (eth_iface) {
        struct in6_addr addr, nexthop;
        net_ipv6_addr_create(&addr, 0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 1);
        net_ipv6_addr_create(&nexthop, 0x2001, 0xdb8, 0x200, 0, 0, 0, 0, 1);
        if (net_route_add(eth_iface, &addr, 64, &nexthop, 3600, 255)) {
            LOG_INF("Added IPv6 route 2001:db8:1::/64 via USB");
        } else {
            LOG_ERR("Failed to add route for 2001:db8:1::/64 via USB");
        }
    }

    if (usb_iface) {
        struct in6_addr addr, nexthop;
        net_ipv6_addr_create(&addr, 0x2001, 0xdb8, 0x200, 0, 0, 0, 0, 1);
        net_ipv6_addr_create(&nexthop, 0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 1);
        if (net_route_add(usb_iface, &addr, 64, &nexthop, 3600, 255)) {
            LOG_INF("Added IPv6 route 2001:db8:2::/64 via Ethernet");
        } else {
            LOG_ERR("Failed to add route for 2001:db8:2::/64 via Ethernet");
        }
    }
}

static void assign_ipv6_addresses(void) {
    struct net_if *eth_iface = net_if_get_by_index(1); 
    struct net_if *usb_iface = net_if_get_by_index(2); 
    struct in6_addr addr;
    
    if (eth_iface) {
        net_ipv6_addr_create(&addr, 0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 1);
        if (net_if_ipv6_addr_add(eth_iface, &addr, NET_ADDR_MANUAL, 0)) {
            LOG_INF("Assigned IPv6 2001:db8:1::1 to eth0");
        } else {
            LOG_ERR("Failed to assign IPv6 2001:db8:1::1 to eth0");
        }
        
    } else {
        LOG_ERR("Ethernet interface not found");
    }

    if (usb_iface) {
        net_ipv6_addr_create(&addr, 0x2001, 0xdb8, 0x200, 0, 0, 0, 0, 1);
        if (net_if_ipv6_addr_add(usb_iface, &addr, NET_ADDR_MANUAL, 0)) {
            LOG_INF("Assigned IPv6 2001:db8:2::1 to USB");
        } else {
            LOG_ERR("Failed to assign IPv6 2001:db8:2::1 to USB");
        }
        
    } else {
        LOG_ERR("USB interface not found");
    }
    
}

int main(void)
{
    struct net_if *eth_iface= net_if_get_by_index(1); 
    struct net_if *usb_iface = net_if_get_by_index(2); 
    
    LOG_INF("Run dhcpv4 client");

	net_mgmt_init_event_callback(&mgmt_cb, handler,
				     NET_EVENT_IPV4_ADDR_ADD);
	net_mgmt_add_event_callback(&mgmt_cb);

    if (init_usb() != 0) {
        LOG_ERR("Failed to initialize USB");
        return -1;
    }
    
    

	net_dhcpv4_init_option_callback(&dhcp_cb, option_handler,
					DHCP_OPTION_NTP, ntp_server,
					sizeof(ntp_server));

	net_dhcpv4_add_option_callback(&dhcp_cb);
     
    netusb_enable(&my_netusb_function);

    // assign_ipv6_addresses();
    discover_and_add_neighbors();
    add_ipv6_routes();
 
	return 0;
}