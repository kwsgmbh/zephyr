/* Networking DHCPv4 client */

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

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_mgmt.h>

#include <zephyr/usb/usb_device.h>
#include <zephyr/net/net_pkt.h>
#include "netusb.h"

#include <zephyr/net/net_if.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/phy.h>

#include "eth_lan865x_priv.h"



#define DHCP_OPTION_NTP (42)

static uint8_t ntp_server[4];

static struct net_mgmt_event_callback mgmt_cb;

static struct net_dhcpv4_option_callback dhcp_cb;

#define APP_ADD 1


#if APP_ADD
static struct net_if *eth_iface;
static struct net_if *net_usb;
int netusb_send( const struct device *dev, struct net_pkt *pkt);

static int my_connect_media(bool status)
{
    LOG_INF("Media connection status: %s", status ? "connected" : "disconnected");
    return 0;
}

static int my_send_pkt(struct net_pkt *pkt)
{
    LOG_INF("Sendingxx packet, length: %zu", net_pkt_get_len(pkt));
    
int ret = lan865x_port_send(eth_iface->if_dev->dev, pkt);
   
    if (ret < 0) {
        LOG_ERR("Failed to send data, error %d", ret);
    } else {
        LOG_INF(" lan865x_port_send Data sent successfully");
    }

     
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






#endif



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

#if APP_ADD

static void init_ip(void) {

eth_iface = net_if_get_default();
net_usb = net_if_get_by_index(2);


if (eth_iface) {
        assign_static_ip(eth_iface, "192.168.1.2", "255.255.255.0", "192.168.1.254");
    } else {
        LOG_ERR("Failed to get LAN interface");
    }

    if (net_usb) {
        assign_static_ip(net_usb, "192.168.1.3", "255.255.255.0", "192.168.1.254");
    } else {
        LOG_ERR("Failed to get USB interface");
    }


}




static void send_sample_data(void) {
		struct net_pkt *pkt;
    int ret;

eth_iface = net_if_get_default();
net_usb = net_if_get_by_index(2);
LOG_INF("Start on name xxxx %s  ", net_if_get_device(eth_iface)->name);
LOG_INF("Startxx %s", net_usb->if_dev->dev->name);



   netusb_enable(&my_netusb_function);

    // Initialize the network packet
    pkt = net_pkt_alloc_with_buffer(net_if_get_default(), 128, AF_INET, 0, K_NO_WAIT);
    if (!pkt) {
        LOG_ERR("Failed to allocate network packet");
        return -1;
    }
	else{

		LOG_INF(" allocate network packet");
	}

    // Add simple data to the network packet (e.g., "Hello, World!")
    const char *data = "Hello, World!";
    ret = net_pkt_write(pkt, data, strlen(data));
    if (ret < 0) {
        LOG_ERR("Failed to write data to packet");
        net_pkt_unref(pkt);
        return -1;
    }

else{

		LOG_INF("  write data to packet");
	}
    // Initialize the packet cursor (it’s needed before sending the packet)
    net_pkt_cursor_init(pkt);

	    // Call the netusb_send function to send the packet
   // ret = netusb_send(net_usb->if_dev->dev, pkt);

	 netusb_send(eth_iface->if_dev->dev, pkt);



 

}

#endif


int   main(void)
{

    eth_iface = net_if_get_default();
	LOG_INF("Run dhcpv4 client");


	    if (init_usb() != 0) {
        LOG_ERR("Failed to initialize USB");
        return -1;
    }






init_ip();

send_sample_data();


while(1){

//send_sample_data();

//int ret =  lan865x_check_spi(eth_iface->if_dev->dev);

// int ret = lan865x_init(eth_iface->if_dev->dev);

// printf("return value os spi %d \n",ret);
printf("sending \n");
k_msleep(5000);


}


#if 0
	net_mgmt_init_event_callback(&mgmt_cb, handler,
				     NET_EVENT_IPV4_ADDR_ADD);
	net_mgmt_add_event_callback(&mgmt_cb);
	net_dhcpv4_init_option_callback(&dhcp_cb, option_handler,
					DHCP_OPTION_NTP, ntp_server,
					sizeof(ntp_server));

	net_dhcpv4_add_option_callback(&dhcp_cb);

	net_if_foreach(start_dhcpv4_client, NULL);





	



#endif


	return 0;
}
