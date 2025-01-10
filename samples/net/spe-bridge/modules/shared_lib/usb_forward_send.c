#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(usb_send, LOG_LEVEL_DBG);
#include <usb_forward_send.h>
#include <print_packet.h>

//struct net_if *eth_iface1 = NULL ;
struct net_if *usb_iface1 = NULL ;


//struct net_if *usb_iface = net_if_get_by_name("USB");
//struct net_if *lan_iface = net_if_get_default();
/* Function to forward a packet from one interface to another */


//int forward_packet(struct net_if *src_iface, struct net_if *dest_iface, struct net_pkt *pkt) {
int forward_packet_send(struct net_pkt *pkt) {

    //eth_iface1 = net_if_get_by_index(1); // LAN interface
    usb_iface1 = net_if_get_by_index(2);// USB interface

    LOG_DBG("Entered USB forward function.");
    //display_net_pkt_details(pkt);
    if (!pkt || !usb_iface1) {
        LOG_ERR("Invalid packet or destination interface");
        return -EINVAL;
    }

    
    LOG_INF("featched the interface usb send-> %p\n", usb_iface1);

    /* Reference the packet for forwarding */
    //net_pkt_ref(pkt);

    net_pkt_iface(pkt) == usb_iface1;

    /* Send the packet to the destination interface */
    if (net_recv_data(usb_iface1, pkt) < 0) {
        LOG_INF("Failed to forward packet");
        net_pkt_unref(pkt);
        return -EIO;
    }

    // LOG_DBG("Packet forwarded from %s to %s",
    //         net_if_get_device(src_iface)->name,
    //         net_if_get_device(dest_iface)->name);
    return 0;
}
