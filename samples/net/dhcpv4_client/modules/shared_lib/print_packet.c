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



void display_net_pkt_details(const struct net_pkt *pkt) {
    if (!pkt) {
        LOG_ERR("Packet is NULL");
        return;
    }

    /* Initialize cursor */
    net_pkt_cursor_init(pkt);

    /* Read and print IPv4 header */
    struct net_ipv4_hdr ipv4_hdr;
    if (net_pkt_read(pkt, &ipv4_hdr, sizeof(ipv4_hdr)) == 0) {
        LOG_INF("IPv4 src: %s", net_sprint_ipv4_addr(&ipv4_hdr.src));
        LOG_INF("IPv4 dst: %s", net_sprint_ipv4_addr(&ipv4_hdr.dst));
    } else {
        LOG_ERR("Failed to read IPv4 header");
        return;
    }

    /* Read and print TCP header */
    struct net_tcp_hdr tcp_hdr;
    if (net_pkt_read(pkt, &tcp_hdr, sizeof(tcp_hdr)) == 0) {
        LOG_INF("TCP src port: %d", ntohs(tcp_hdr.src_port));
        LOG_INF("TCP dst port: %d", ntohs(tcp_hdr.dst_port));
    } else {
        LOG_ERR("Failed to read TCP header");
        return;
    }

    /* Print remaining payload data */
    uint8_t payload[128]; /* Adjust size as needed */
    size_t payload_len = net_pkt_remaining_data(pkt);

    if (payload_len > sizeof(payload)) {
        LOG_WRN("Payload too large, truncating output");
        payload_len = sizeof(payload);
    }

    if (net_pkt_read(pkt, payload, payload_len) == 0) {
        LOG_INF("Payload (hex):");
        for (size_t i = 0; i < payload_len; i++) {
            printk("%02X ", payload[i]);
        }
        printk("\n");
    } else {
        LOG_ERR("Failed to read payload");
    }
}