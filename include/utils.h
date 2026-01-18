#include <linux/if_ether.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include "Arguments.h"
#include "main.h"

static std::string mon_ifname_for_mac(const std::array<uint8_t, ETH_ALEN>& mac) {
    auto& macs = Arguments::arguments.macs;
    std::optional<uint32_t> index = std::nullopt;
    for (size_t i = 0; i < macs.size(); i++) {
        if (macs[i] == mac) {
            index = i;
            break;
        }
    }

    if (index.has_value()) {
        return std::string(MONITOR_INTERFACE_NAME) + "_sp" + std::to_string(index.value());
    }

    return std::string(MONITOR_INTERFACE_NAME);
}
