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
 //static bool promiscuous_mode_enabled = false;
 
 static struct __netusb {
	 struct net_if *iface;
	 const struct netusb_function *func;
 } netusb;
 
 static struct net_if *eth_iface = NULL;
 
 
 
 static int netusb_send(const struct device *dev, struct net_pkt *pkt)
 {
	 int ret;
 
	 ARG_UNUSED(dev);
 
	 //LOG_DBG("Send pkt, len %zu", net_pkt_get_len(pkt));
	 LOG_INF("....netusb_send....");
 
	 //LOG_HEXDUMP_INF(net_pkt_data(pkt), net_pkt_get_len(pkt), "Packet data dump");
 
	 display_net_pkt_details(pkt);
	 
 
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
	 //LOG_DBG("Recv pkt %p, len %zu", pkt, net_pkt_get_len(pkt));
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
	 static uint8_t mac[6] = { 0x00, 0x00, 0x5E, 0x00, 0x53, 0x01 };
 
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