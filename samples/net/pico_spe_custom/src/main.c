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
#include <zephyr/net/dhcpv4_server.h>  // For DHCP server
// #include <zephyr/subsys/net/ip/route.h>
// #include <zephyr/subsys/net/l2/ethernet/bridge.h>

#define DHCP_OPTION_NTP (42)

static uint8_t ntp_server[4];

static struct net_mgmt_event_callback mgmt_cb;

static struct net_dhcpv4_option_callback dhcp_cb;

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
    if (net_addr_pton(AF_INET, "192.168.2.100", &base_addr) < 0) {
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

    ret = usb_enable(NULL);
    if (ret != 0) {
        LOG_ERR("USB enable error %d", ret);
        return ret;
    }

    return 0;
}


int main(void)
{
	struct net_if *iface_bridge = net_if_get_by_index(1);
    struct net_if *iface_lan = net_if_get_by_index(2); // LAN interface
    struct net_if *iface_usb = net_if_get_by_index(3); // USB interface
    
    LOG_INF("Run dhcpv4 client");

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
    
  
    
    if (iface_lan) {
        assign_static_ip(iface_lan, "192.168.1.2", "255.255.255.0", "192.168.1.254");
    } else {
        LOG_ERR("Failed to get LAN interface");
    }

    if (iface_usb) {
        assign_static_ip(iface_usb, "192.168.1.3", "255.255.255.0", "192.168.1.254");
    } else {
        LOG_ERR("Failed to get USB interface");
    }
    if (iface_bridge) {
        assign_static_ip(iface_lan, "192.168.1.4", "255.255.255.0", "192.168.1.254");
        net_if_up(iface_bridge);
    } else {
        LOG_ERR("Failed to get LAN interface");
    }
    // setup_routing();

	net_if_foreach(start_dhcpv4_client, NULL);
	return 0;
}