#!/usr/bin/env bash

build_firewall_offload() {
	export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig/
	make -j 8
}

build_firewall_offload
