# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

set(DTC_OVERLAY_FILE ${CMAKE_CURRENT_SOURCE_DIR}/boards/pico-spe.overlay)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(dhcpv4_client)
target_include_directories(app PRIVATE ${ZEPHYR_BASE}/subsys/net/ip)
target_include_directories(app PRIVATE ${ZEPHYR_BASE}/subsys/net/l2/ethernet)

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})
