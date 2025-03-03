# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(dhcpv4_client)
target_include_directories(app PRIVATE ${ZEPHYR_BASE}/subsys/net/ip)
target_include_directories(app PRIVATE ${ZEPHYR_BASE}/subsys/net/l2/ethernet)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_LIST_DIR}/modules/shared_lib)
FILE(GLOB app_sources src/*.c ${CMAKE_CURRENT_LIST_DIR}/modules/shared_lib/print_packet.c)
target_sources(app PRIVATE ${app_sources})
