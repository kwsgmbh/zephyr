#include <stdio.h>
#include <inttypes.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_context.h>
#include <zephyr/logging/log.h>
#include <print_packet.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(packet_monitor, LOG_LEVEL_DBG);

#include "net_private.h"



void display_net_pkt_details(struct net_pkt *pkt) {

       struct net_pkt *pkt_copy = net_pkt_clone(pkt, K_NO_WAIT);
    if (!pkt_copy) {
        LOG_ERR("Failed to clone the packet");
        return;
    }
    net_pkt_cursor_init(pkt_copy);

    struct net_ipv4_hdr ipv4_hdr;
    if (net_pkt_read(pkt_copy, &ipv4_hdr, sizeof(ipv4_hdr)) == 0) {
        LOG_INF("ipv4 src: %s", net_sprint_ipv4_addr(&ipv4_hdr.src));
        LOG_INF("ipv4 dst: %s", net_sprint_ipv4_addr(&ipv4_hdr.dst));
    } else {
        LOG_ERR("Failed to read IPv4 header from cloned packet");
    }

    net_pkt_unref(pkt_copy);
}