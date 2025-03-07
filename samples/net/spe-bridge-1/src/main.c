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
 #include <zephyr/net/net_pkt.h>
 #include <zephyr/net/net_if.h>
 #include <zephyr/net/net_core.h>
 #include <zephyr/net/net_context.h>
 #include <zephyr/net/net_mgmt.h>
 #include <zephyr/usb/usb_device.h>
 #include <zephyr/net/ethernet_bridge.h>
 
 #define ETH_IFACE_IDX    2
 #define USB_IFACE_IDX    3
 #define BRIDGE_IFACE_IDX 1
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
 
 // static void start_dhcpv4_server(struct net_if *iface)
 // {
 //     int ret;
 //     struct in_addr base_addr;
 //     LOG_INF("entered into start server function\n");
 //     if (net_addr_pton(AF_INET, "192.168.1.4", &base_addr) < 0) {
 //         LOG_ERR("Invalid base address for DHCP server");
 //         return;
 //     }
 
 //     LOG_INF("Start DHCP server on %s: index=%d", net_if_get_device(iface)->name,
 //             net_if_get_by_iface(iface));
 
 //     ret = net_dhcpv4_server_start(iface, &base_addr);
 //     if (ret != 0) {
 //         LOG_ERR("Failed to start DHCP server: %d", ret);
 //     }
 // }
 
 static void assign_static_ip(struct net_if *iface, const char *ip, const char *netmask, const char *gateway)
 {
     struct in_addr addr, netmask_addr, gateway_addr;
 
     // LOG_INF("Assigning static IP %s to %s", ip, net_if_get_device(iface)->name);
 
     // if (net_addr_pton(AF_INET, ip, &addr) < 0 ||
     //     net_addr_pton(AF_INET, netmask, &netmask_addr) < 0 ||
     //     net_addr_pton(AF_INET, gateway, &gateway_addr) < 0) {
     //     LOG_ERR("Invalid static IP configuration");
     //     return;
     // }
 
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
         printk("usb enable error %d\n", ret);
     }
     return 0;
 
 }
 
 int main(void)
 {
     init_usb();
     LOG_INF("Run dhcpv4 client");
 
     struct net_if *brdge_iface = net_if_get_by_index(BRIDGE_IFACE_IDX);
     struct net_if *eth_iface   = net_if_get_by_index(ETH_IFACE_IDX);
     struct net_if *usb_iface   = net_if_get_by_index(USB_IFACE_IDX);
 
     if(brdge_iface && eth_iface && usb_iface){
 
         int ret = 0;
 
         LOG_INF("bridging ");
         ret = eth_bridge_iface_add(brdge_iface, usb_iface);
         if (ret < 0){
             LOG_ERR("error: bridge eth_iface add (%d)\n", ret);
         }
         ret = eth_bridge_iface_add(brdge_iface, eth_iface);
         if (ret < 0){
             LOG_ERR("error: bridge usb_iface add (%d) \n", ret); 
         }
         k_msleep(2000);
         net_if_up(brdge_iface);
         LOG_INF("Network bridge interface is up");
     }
 
     net_mgmt_init_event_callback(&mgmt_cb, handler,
                      NET_EVENT_IPV4_ADDR_ADD);
     net_mgmt_add_event_callback(&mgmt_cb);
 
     net_dhcpv4_init_option_callback(&dhcp_cb, option_handler,
                     DHCP_OPTION_NTP, ntp_server,
                     sizeof(ntp_server));
 
     net_dhcpv4_add_option_callback(&dhcp_cb);
 
     net_if_foreach(start_dhcpv4_client, NULL);
 
     
 
     
      
 
     // net_pkt_filter_register(iface1, packet_filter_callback, iface2);
 
     // /* Register packet filter for iface2 -> iface1 */
     // net_pkt_filter_register(iface2, packet_filter_callback, iface1);
 
     // if (eth_iface) {
     //     assign_static_ip(eth_iface, "192.178.1.2", "255.255.255.0", "192.178.1.1");
     // } else {
     //     LOG_ERR("Failed to get LAN interface");
     // }
 
     // if (usb_iface) {
     //     assign_static_ip(usb_iface, "192.178.1.3", "255.255.255.0", "192.178.1.1"); // change to 3
     // } else {
     //     LOG_ERR("Failed to get USB interface");
     // }
 
    // configure bridge
 
     
 
     return 0;
 }