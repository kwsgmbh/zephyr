// / Networking DHCPv4 client with USB Network Bridging /

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
#include <zephyr/net/net_config.h>

#define DHCP_OPTION_NTP (42)

static uint8_t ntp_server[4];

static struct net_mgmt_event_callback mgmt_cb;
static struct net_dhcpv4_option_callback dhcp_cb;

static struct net_if *eth_iface;
static struct net_if *usb_iface;

static struct net_if_link_cb eth_link_cb;
static struct net_if_link_cb usb_link_cb;
// / Forward packets from one interface to another /
static void forward_packet(struct net_pkt *pkt, struct net_if *dest_iface)
{
    if (!pkt || !dest_iface) {
        LOG_ERR("Invalid packet or interface");
        return;
    }

    net_pkt_ref(&pkt);

    if (net_recv_data(dest_iface, pkt) < 0) {
        LOG_ERR("Packet forwarding failed");
        net_pkt_unref(pkt);
    } else {
        LOG_DBG("Packet forwarded successfully");
    }
}

// / Ethernet packet handler /
static void eth_recv_cb(struct net_if *iface, struct net_pkt *pkt)
{
    LOG_DBG("Packet received on Ethernet");
    if (iface == eth_iface) {
        forward_packet(&pkt, usb_iface);
    }
}

// / USB packet handler /
static void usb_recv_cb(struct net_if *iface, struct net_pkt pkt)
{
    LOG_DBG("Packet received on USB");
    if (iface == usb_iface) {
        forward_packet(&pkt, eth_iface);
    }
}

static void start_dhcpv4_client(struct net_if *iface, void *user_data)
{
    ARG_UNUSED(user_data);

    LOG_INF("Start DHCPv4 on %s: index=%d", net_if_get_device(iface)->name,
            net_if_get_by_iface(iface));
    net_dhcpv4_start(iface);
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

        if (iface->config.ip.ipv4->unicast[i].ipv4.addr_type != NET_ADDR_DHCP) {
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

void list_interfaces(struct net_if *iface, void *user_data)
{
    if (iface) {
        LOG_INF("Interface: %s, Index: %d", net_if_get_device(iface)->name,
                net_if_get_by_iface(iface));
        
        // If you are looking for specific interfaces like "eth_netusb":
        if (strcmp(net_if_get_device(iface)->name, "eth_netusb") == 0) {
            usb_iface = iface;  // Found USB interface
            LOG_INF("USB Interface found: %s", net_if_get_device(iface)->name);
        }
    }
}


int main(void)
{
    LOG_INF("Run DHCPv4 client with USB bridging");

    if (init_usb() != 0) {
        LOG_ERR("Failed to initialize USB");
        return -1;
    }
	net_if_foreach(list_interfaces, NULL);
    // / Get the default network interfaces /
    eth_iface = net_if_get_default();
    if (!eth_iface) {
        LOG_ERR("Failed to get default Ethernet interface");
        return -1;
    }
    
    LOG_INF("VALUE OF ETH IFACE IS %d\n",eth_iface);
    
     if (!usb_iface) {
        LOG_ERR("USB interface not found");
        return -1;
    }

    LOG_INF("VALUE OF USB IFACE IS %d\n",usb_iface);

    if (!eth_iface || !usb_iface) {
        LOG_ERR("Failed to get network interfaces");
        return -1;
    }

    // / Set up packet callbacks /
    // net_if_register_link_cb(eth_iface, eth_recv_cb);
    // net_if_register_link_cb(usb_iface, usb_recv_cb);
    net_if_register_link_cb(&eth_link_cb, eth_recv_cb);
    LOG_INF("Ethernet callback registered");

    // Register the USB receive callback
    net_if_register_link_cb(&usb_link_cb, usb_recv_cb);
    LOG_INF("USB callback registered");
    // / Initialize DHCP and event callbacks /
    net_mgmt_init_event_callback(&mgmt_cb, handler,
                                 NET_EVENT_IPV4_ADDR_ADD);
    net_mgmt_add_event_callback(&mgmt_cb);

    net_dhcpv4_init_option_callback(&dhcp_cb, option_handler,
                                    DHCP_OPTION_NTP, ntp_server,
                                    sizeof(ntp_server));

    net_dhcpv4_add_option_callback(&dhcp_cb);

    // / Start DHCPv4 client on all interfaces /
    net_if_foreach(start_dhcpv4_client, NULL);

    LOG_INF("Bridge initialized successfully");

    return 0;
}
