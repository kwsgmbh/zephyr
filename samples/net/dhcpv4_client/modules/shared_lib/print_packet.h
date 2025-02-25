#ifndef PRINT_PACKET_H
#define PRINT_PACKET_H
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>


// extern struct net_if *eth_iface1;
// extern struct net_if *usb_iface1;



void display_net_pkt_details(const struct net_pkt *pkt);

#endif /* PRINT_PACKET_H */