
/*
 * Copyright (c) 2017 ARM Ltd.
 * Copyright (c) 2016 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_dhcpv4_client_sample, LOG_LEVEL_DBG);

#include <zephyr/kernel.h>
#include <zephyr/linker/sections.h>
#include <errno.h>
#include <stdio.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_mgmt.h>

struct net_if *eth_iface = NULL;
struct net_if *usb_iface = NULL;

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
 

int init_usb(void)
{
	int ret;

	ret = usb_enable(NULL);
	if (ret != 0) {
		printk("usb enable error %d\n", ret);
	}
	return 0;
}
int main(void)
{
	LOG_INF("Run SPE Bridge");
	
	init_usb();

	eth_iface = net_if_get_by_index(1); // LAN interface
    usb_iface = net_if_get_by_index(2); // USB interface

	init_usb();

	if (eth_iface) {
        assign_static_ip(eth_iface, "192.168.1.10", "255.255.255.0", "192.168.1.1");
    } else {
        LOG_ERR("Failed to get LAN interface");
    }

    if (usb_iface) {
        assign_static_ip(usb_iface, "192.168.2.10", "255.255.255.0", "192.168.2.1");
    } else {
        LOG_ERR("Failed to get USB interface");
    }
	
	return 0;
	
}
