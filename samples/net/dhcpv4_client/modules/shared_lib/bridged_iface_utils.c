#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(shared_net_utils, LOG_LEVEL_DBG);
#include <bridged_iface_utils.h>

//struct net_if *usb_iface = net_if_get_by_name("USB");
//struct net_if *lan_iface = net_if_get_default();
/* Function to forward a packet from one interface to another */
int forward_packet(struct net_if *src_iface, struct net_if *dest_iface, struct net_pkt *pkt) {
    if (!pkt || !dest_iface) {
        LOG_ERR("Invalid packet or destination interface");
        return -EINVAL;
    }

    /* Reference the packet for forwarding */
    net_pkt_ref(pkt);

    /* Send the packet to the destination interface */
    if (net_recv_data(dest_iface, pkt) < 0) {
        LOG_ERR("Failed to forward packet");
        net_pkt_unref(pkt);
        return -EIO;
    }

    LOG_DBG("Packet forwarded from %s to %s",
            net_if_get_device(src_iface)->name,
            net_if_get_device(dest_iface)->name);
    return 0;
}
