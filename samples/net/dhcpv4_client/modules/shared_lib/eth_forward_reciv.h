#ifndef ETH_FORWAD_RECIV_H
#define ETH_FORWAD_RECIV_H
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>


// extern struct net_if *eth_iface1;
// extern struct net_if *usb_iface1;



int forward_packet_receive(struct net_pkt *pkt);

#endif /* ETH_FORWAD_RECIV */