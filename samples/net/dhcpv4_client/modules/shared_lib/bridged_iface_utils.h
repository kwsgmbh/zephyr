#ifndef BRIDGED_IFACE_UTILS_H
#define BRIDGED_IFACE_UTILS_H
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>

extern struct net_if *eth_iface;
extern struct net_if *usb_iface;

int forward_packet(struct net_if *src_iface, struct net_if *dest_iface, struct net_pkt *pkt);

#endif /* BRIDGED_IFACE_UTILS_H */