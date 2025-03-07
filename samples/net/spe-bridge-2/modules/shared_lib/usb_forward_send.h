#ifndef USB_FORWARD_SEND_H
#define USB_FORWARD_SEND_H
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>


// extern struct net_if *eth_iface1;
// extern struct net_if *usb_iface1;



int forward_packet_send(struct net_pkt *pkt);

#endif /* USB_FORWARD_SEND_H */