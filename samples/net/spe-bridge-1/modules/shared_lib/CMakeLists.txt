zephyr_library()

zephyr_library_sources(${CMAKE_CURRENT_LIST_DIR}/shared_lib/eth_forward_reciv.c)
zephyr_library_sources(${CMAKE_CURRENT_LIST_DIR}/shared_lib/usb_forward_send.c)
zephyr_library_sources(${CMAKE_CURRENT_LIST_DIR}/shared_lib/print_packet.c)
