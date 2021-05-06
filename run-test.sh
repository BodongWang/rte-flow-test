#!/bin/sh

APP=build/rte-flow-test

if [ ! -f $APP ]; then
	echo "Error: $APP is not compiled, run build.sh"
	return
fi

LD_LIBRARY_PATH=/opt/mellanox/dpdk/lib/aarch64-linux-gnu/ $APP -n 1 -a 0000:03:00.0,reclaim_mem_mode=2 -a 0000:03:00.1,reclaim_mem_mode=2
