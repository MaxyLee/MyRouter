#include "router_hal.h"

// configure this to match the output of `ip a`
const char *interfaces[N_IFACE_ON_BOARD] = {
    "veth-R2-1",
    "veth-R2-2",
    "eth3",
    "eth4",
};
