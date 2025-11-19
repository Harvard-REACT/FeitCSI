/*
 * FeitCSI is the tool for extracting CSI information from supported intel NICs.
 * Copyright (C) 2023-2025 Miroslav Hutar.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "WiFIController.h"
#include "Arguments.h"
#include "Logger.h"
#include "Netlink.h"
#include "main.h"
#include "nl80211.h"

#include <errno.h>
#include <iwlib.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/route/link.h>
#include <optional>
#include <thread>
#include <vector>

void WiFIController::getAllInterfaces() {
    std::vector<InterfaceInfoBuilder> interfaces;

    Cmd get_interface_cmd{
        .id = NL80211_CMD_GET_INTERFACE,
        .idby = CIB_NONE,
        .nlFlags = NLM_F_DUMP,
        .device = 0,
        .pre_execute_handler = NULL,
        .valid_handler = this->getInterfaceInfoHandler,
        .valid_handler_args = (void*)&interfaces,
    };

    this->nlExecCommand(get_interface_cmd);

    for (auto& builder : interfaces) {
        // Invariant: all builders in the list have interfaceIndex set
        uint32_t interfaceIndex = builder.interfaceIndex().value();

        Cmd get_tx_power_cmd{
            .id = NL80211_CMD_GET_WIPHY,
            .idby = CIB_NETDEV,
            .nlFlags = NLM_F_DUMP,
            .device = interfaceIndex,
            .pre_execute_handler = NULL,
            .valid_handler = this->getInterfaceInfoTxPowerHandler,
            .valid_handler_args = (void*)&builder,
        };

        this->nlExecCommand(get_tx_power_cmd);

        std::optional<InterfaceInfo> info = builder.build();
        if (!info.has_value()) {
            continue;
        }
        this->interfaces[info.value().ifName] = info.value();
    }
}

std::optional<InterfaceInfo> WiFIController::getInterfaceInfo(const std::string interfaceName) {
    std::vector<InterfaceInfoBuilder> interfaces;

    Cmd cmd{
        .id = NL80211_CMD_GET_INTERFACE,
        .idby = CIB_NETDEV,
        .nlFlags = 0,
        .device = if_nametoindex(interfaceName.c_str()),
        .pre_execute_handler = NULL,
        .valid_handler = this->getInterfaceInfoHandler,
        .valid_handler_args = (void*)&interfaces,
    };

    this->nlExecCommand(cmd);

    if (interfaces.empty()) {
        return std::nullopt;
    }

    if (interfaces.size() > 1) {
        Logger::log(warning) << "Multiple interfaces found with name " << interfaceName
                             << ". Using the first one.\n";
    }

    InterfaceInfoBuilder builder = interfaces[0];
    // Invariant: builder has to have interfaceIndex set
    uint32_t interfaceIndex = builder.interfaceIndex().value();

    Cmd get_tx_power_cmd{
        .id = NL80211_CMD_GET_WIPHY,
        .idby = CIB_NETDEV,
        .nlFlags = NLM_F_DUMP,
        .device = interfaceIndex,
        .pre_execute_handler = NULL,
        .valid_handler = this->getInterfaceInfoTxPowerHandler,
        .valid_handler_args = (void*)&builder,
    };

    this->nlExecCommand(get_tx_power_cmd);

    std::optional<InterfaceInfo> info = builder.build();
    if (!info.has_value()) {
        return std::nullopt;
    }
    this->interfaces[info.value().ifName] = info.value();

    return info;
}

std::optional<InterfaceInfo> WiFIController::getInterfaceInfo(uint32_t interfaceIndex) {
    Cmd cmd{
        .id = NL80211_CMD_GET_INTERFACE,
        .idby = CIB_NETDEV,
        .nlFlags = 0,
        .device = interfaceIndex,
        .pre_execute_handler = NULL,
        .valid_handler = this->getInterfaceInfoHandler,
    };

    this->nlExecCommand(cmd);

    for (const auto& [_, interfaceInfo] : interfaces) {
        if (interfaceInfo.ifIndex == interfaceIndex) {
            return interfaceInfo;
        }
    }

    return std::nullopt;
}

int WiFIController::getInterfaceInfoHandler(struct nl_msg* msg, void* arg) {
    void** arguments = (void**)arg;
    WiFIController* instance = (WiFIController*)arguments[0];
    std::vector<InterfaceInfoBuilder>* builders = (std::vector<InterfaceInfoBuilder>*)arguments[1];

    struct genlmsghdr* gnl_header = (genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr* attribute_table[NL80211_ATTR_MAX + 1];
    InterfaceInfoBuilder ifInfo;

    int err = nla_parse(attribute_table, NL80211_ATTR_MAX, genlmsg_attrdata(gnl_header, 0),
                        genlmsg_attrlen(gnl_header, 0), NULL);
    if (err < 0) {
        Logger::log(error) << "Unable to parse attribute table for Netlink message: " << err
                           << "\n";
        return err;
    }

    if (attribute_table[NL80211_ATTR_IFNAME]) {
        ifInfo.interfaceName(nla_get_string(attribute_table[NL80211_ATTR_IFNAME]));
    }

    if (attribute_table[NL80211_ATTR_IFTYPE]) {
        ifInfo.interfaceType((nl80211_iftype)nla_get_u32(attribute_table[NL80211_ATTR_IFTYPE]));
    }

    if (attribute_table[NL80211_ATTR_IFINDEX]) {
        ifInfo.interfaceIndex(nla_get_u32(attribute_table[NL80211_ATTR_IFINDEX]));
    }

    if (attribute_table[NL80211_ATTR_WIPHY]) {
        ifInfo.phyIndex(nla_get_u32(attribute_table[NL80211_ATTR_WIPHY]));
    }

    if (attribute_table[NL80211_ATTR_WDEV]) {
        ifInfo.wdevIndex(nla_get_u64(attribute_table[NL80211_ATTR_WDEV]));
    }

    if (attribute_table[NL80211_ATTR_MAC]) {
        ifInfo.mac(
            instance->mac_n2a((const unsigned char*)nla_data(attribute_table[NL80211_ATTR_MAC])));
    }

    if (attribute_table[NL80211_ATTR_WIPHY_FREQ]) {
        ifInfo.frequency(nla_get_u32(attribute_table[NL80211_ATTR_WIPHY_FREQ]));
    }

    if (attribute_table[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]) {
        Logger::log(info) << ("Magically received tx power!\n");
        ifInfo.txPowerDbm(nla_get_u32(attribute_table[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]) / 100);
    }

    if (attribute_table[NL80211_ATTR_IFINDEX]) {
        ifInfo.interfaceIndex(nla_get_u32(attribute_table[NL80211_ATTR_IFINDEX]));
        builders->push_back(ifInfo);
    }

    return NL_OK;
}

int WiFIController::getInterfaceInfoTxPowerHandler(struct nl_msg* msg, void* arg) {
    void** arguments = (void**)arg;
    InterfaceInfoBuilder* builder = (InterfaceInfoBuilder*)arguments[1];

    struct genlmsghdr* gnl_header = (genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr* attribute_table[NL80211_ATTR_MAX + 1];

    int err = nla_parse(attribute_table, NL80211_ATTR_MAX, genlmsg_attrdata(gnl_header, 0),
                        genlmsg_attrlen(gnl_header, 0), NULL);
    if (err < 0) {
        Logger::log(error) << "Unable to parse attribute table for Netlink message: " << err
                           << "\n";
        return err;
    }

    if (attribute_table[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]) {
        int32_t tx_power_mbm = nla_get_s32(attribute_table[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]);
        int32_t tx_power_dbm = tx_power_mbm / 100;
        builder->txPowerDbm(tx_power_dbm);
        return NL_STOP;
    }

    return NL_OK;
}

int WiFIController::abortScan(const std::string interfaceName) {
    Cmd cmd{
        .id = NL80211_CMD_ABORT_SCAN,
        .idby = CIB_NETDEV,
        .nlFlags = 0,
        .device = if_nametoindex(interfaceName.c_str()),
        .pre_execute_handler = nullptr,
        .valid_handler = NULL,
    };

    return nlExecCommand(cmd);
}

int WiFIController::setInterfaceTxPower(const std::string interfaceName, int32_t power_dbm) {
    Cmd cmd{
        .id = NL80211_CMD_SET_WIPHY,
        .idby = CIB_NETDEV,
        .nlFlags = 0,
        .device = if_nametoindex(interfaceName.c_str()),
        .pre_execute_handler = this->setTxPowerHandler,
        .valid_handler = NULL,
        // Care must be taken to ensure that this pointer's lifetime exceeds the length of
        // the callback. In this case, this function's stack frame expires after the stack frame
        // of the callback.
        .pre_execute_handler_args = (void*)&power_dbm,
    };

    this->nlExecCommand(cmd);

    std::optional<InterfaceInfo> info = getInterfaceInfo(interfaceName);

    if (!info.has_value()) {
        return -1;
    }

    return power_dbm == info.value().txdBm ? 0 : -1;
}

int WiFIController::setInterfaceTxPower(uint32_t interfaceIndex, int32_t power_dbm) {
    Cmd cmd{
        .id = NL80211_CMD_SET_WIPHY,
        .idby = CIB_NETDEV,
        .nlFlags = 0,
        .device = interfaceIndex,
        .pre_execute_handler = this->setTxPowerHandler,
        // Care must be taken to ensure that this pointer's lifetime exceeds the length of
        // the callback. In this case, this function's stack frame expires after the stack frame
        // of the callback.
        .pre_execute_handler_args = (void*)&power_dbm,
    };

    this->nlExecCommand(cmd);

    return power_dbm == getInterfaceInfo(interfaceIndex).value().txdBm ? 0 : -1;
}

int WiFIController::setTxPowerHandler(nl80211_state* state, nl_msg* msg, void* arg) {
    int32_t power_dbm = *(int32_t*)arg;
    int32_t power_mbm = power_dbm * 100;

    NLA_PUT_S32(msg, NL80211_ATTR_WIPHY_TX_POWER_SETTING, NL80211_TX_POWER_FIXED);
    NLA_PUT_S32(msg, NL80211_ATTR_WIPHY_TX_POWER_LEVEL, power_mbm);

    return 0;

nla_put_failure:
    return -ENOBUFS;
}

int WiFIController::createInterface(const std::string interfaceName,
                                    const nl80211_iftype type,
                                    const unsigned char* mac,
                                    uint32_t phyIndex) {
    const void* settings[] = {
        interfaceName.c_str(),
        &type,
        mac,
    };

    Cmd cmd{
        .id = NL80211_CMD_NEW_INTERFACE,
        .idby = CIB_PHY,
        .nlFlags = 0,
        .device = phyIndex,
        .pre_execute_handler = this->createInterfaceHandler,
        .valid_handler = NULL,
        .pre_execute_handler_args = settings,
    };

    this->nlExecCommand(cmd);

    return getInterfaceInfo(interfaceName).has_value() ? 0 : -1;
}

int WiFIController::createInterfaceHandler(struct nl80211_state* state,
                                           struct nl_msg* msg,
                                           void* arg) {
    void** settings = (void**)arg;
    const char* name = (const char*)settings[0];
    const char* mac = (const char*)settings[2];
    nl80211_iftype* type = (nl80211_iftype*)(settings[1]);

    NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, name);
    NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, *type);
    NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, mac);

    return 0;

nla_put_failure:
    return -ENOBUFS;
}

void WiFIController::deleteInterface(const std::string name) {
    Cmd cmd{
        .id = NL80211_CMD_DEL_INTERFACE,
        .idby = CIB_NETDEV,
        .nlFlags = 0,
        .device = if_nametoindex(name.c_str()),
        .pre_execute_handler = NULL,
        .valid_handler = NULL,
    };
    this->nlExecCommand(cmd);
}

void WiFIController::deleteInterface(uint32_t interfaceIndex) {
    Cmd cmd{
        .id = NL80211_CMD_DEL_INTERFACE,
        .idby = CIB_NETDEV,
        .nlFlags = 0,
        .device = interfaceIndex,
        .pre_execute_handler = NULL,
        .valid_handler = NULL,
    };
    this->nlExecCommand(cmd);
}

int WiFIController::setInterfaceFrequency(const std::string interfaceName,
                                          uint32_t frequency_mhz,
                                          const std::string bandwidth) {
    const void* settings[] = {&frequency_mhz, bandwidth.c_str()};

    Cmd cmd{
        .id = NL80211_CMD_SET_WIPHY,
        .idby = CIB_NETDEV,
        .nlFlags = 0,
        .device = if_nametoindex(interfaceName.c_str()),
        .pre_execute_handler = setFrequencyHandler,
        .valid_handler = NULL,
        .pre_execute_handler_args = settings,
    };

    this->nlExecCommand(cmd);

    std::optional<InterfaceInfo> info = getInterfaceInfo(interfaceName);
    if (!info.has_value()) {
        return -ENOENT;
    }

    return info.value().freq == frequency_mhz ? 0 : -1;
}

int WiFIController::setInterfaceFrequency(uint32_t interfaceIndex,
                                          uint16_t frequency,
                                          const std::string bandwidth) {
    const void* settings[] = {&frequency, bandwidth.c_str()};

    Cmd cmd{
        .id = NL80211_CMD_SET_WIPHY,
        .idby = CIB_NETDEV,
        .nlFlags = 0,
        .device = interfaceIndex,
        .pre_execute_handler = setFrequencyHandler,
        .valid_handler = NULL,
        .pre_execute_handler_args = settings,
    };

    this->nlExecCommand(cmd);

    return getInterfaceInfo(interfaceIndex).value().freq == frequency ? 0 : -1;
}

int WiFIController::setFrequencyHandler(struct nl80211_state* state,
                                        struct nl_msg* msg,
                                        void* arg) {
    void** settings = (void**)arg;
    uint16_t frequency = *(uint16_t*)(settings[0]);
    char* bandwidth = (char*)(settings[1]);

    uint32_t freq = frequency;
    uint32_t freq_offset = 0;

    unsigned int control_freq = freq;
    unsigned int control_freq_offset = freq_offset;
    unsigned int center_freq1 = freq;
    unsigned int center_freq1_offset = freq_offset;
    enum nl80211_chan_width width =
        control_freq < 1000 ? NL80211_CHAN_WIDTH_16 : NL80211_CHAN_WIDTH_20_NOHT;

    struct ChanMode selectedChanMode = getChanMode(bandwidth);

    center_freq1 = getCf1(&selectedChanMode, freq);

    /* For non-S1G frequency */
    if (center_freq1 > 1000)
        center_freq1_offset = 0;

    width = (nl80211_chan_width)selectedChanMode.width;

    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, control_freq);
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ_OFFSET, control_freq_offset);
    NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH, width);

    switch (width) {
        case NL80211_CHAN_WIDTH_20_NOHT:
            NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_NO_HT);
            break;
        case NL80211_CHAN_WIDTH_20:
            NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_HT20);
            break;
        case NL80211_CHAN_WIDTH_40:
            if (control_freq > center_freq1) {
                NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_HT40MINUS);
            } else {
                NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_HT40PLUS);
            }
            break;
        default:
            break;
    }

    if (center_freq1) {
        NLA_PUT_U32(msg, NL80211_ATTR_CENTER_FREQ1, center_freq1);
    }

    if (center_freq1_offset) {
        NLA_PUT_U32(msg, NL80211_ATTR_CENTER_FREQ1_OFFSET, center_freq1_offset);
    }

    return 0;

nla_put_failure:
    return -ENOBUFS;
}

int WiFIController::setInterfaceStatus(const std::string interfaceName, bool up) {
    if (!this->nlstate.rnl_socket) {
        Logger::log(error) << "route socket is not initialized\n";
        return -ENOTCONN;
    }

    int err;
    struct rtnl_link* original_link = nullptr;
    if ((err = rtnl_link_get_kernel(this->nlstate.rnl_socket, 0, interfaceName.c_str(),
                                    &original_link)) < 0) {
        Logger::log(error) << "rtnl_link_get_kernel(" << interfaceName << "): " << nl_geterror(err)
                           << "\n";
        return err;
    }

    struct rtnl_link* modified_link = rtnl_link_alloc();
    if (!modified_link) {
        rtnl_link_put(original_link);
        return -NLE_NOMEM;
    }

    rtnl_link_set_ifindex(modified_link, rtnl_link_get_ifindex(original_link));
    if (up)
        rtnl_link_set_flags(modified_link, IFF_UP);
    else
        rtnl_link_unset_flags(modified_link, IFF_UP);

    err = rtnl_link_change(this->nlstate.rnl_socket, original_link, modified_link, 0);

    rtnl_link_put(modified_link);
    rtnl_link_put(original_link);

    if (err < 0) {
        Logger::log(error) << "rtnl_link_change(" << interfaceName << "): " << nl_geterror(err)
                           << "\n";
        return err;
    }

    if (Arguments::arguments.verbose) {
        Logger::log(info) << "Interface " << interfaceName << " has been brought "
                          << (up ? "up" : "down") << "\n";
    }

    return 0;
}

void rfkill_unblock() {
    const char* command = "rfkill unblock all";

    // Execute the command using system()
    int result = system(command);

    // Check the return value to see if the command was successful
    if (result == 0) {
        std::cout << "Successfully executed: " << command << std::endl;
    } else {
        std::cerr << "Failed to execute: " << command << ". Return code: " << result << std::endl;
        // You might want to check errno for more specific error details if needed
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
}

void WiFIController::createMonitorInterface(uint32_t phy_index,
                                            uint32_t frequency,
                                            uint32_t tx_power_dbm,
                                            const unsigned char* mac) {
    int err;
    if (createInterface(MONITOR_INTERFACE_NAME, NL80211_IFTYPE_MONITOR, mac, phy_index) < 0) {
        Logger::log(error) << "Failed to create monitor mode interface\n";
        return;
    }

    if (setInterfaceStatus(MONITOR_INTERFACE_NAME, true) < 0) {
        Logger::log(error) << "Failed to set interface to up\n";
        return;
    };

    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    while ((err = setInterfaceFrequency(MONITOR_INTERFACE_NAME, frequency,
                                        Arguments::arguments.bandwidth.c_str())) < 0) {
        Logger::log(error) << "Failed to set frequency (" << err << ")\n";
        rfkill_unblock();
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

void WiFIController::createApInterface(uint32_t phy_index,
                                       uint32_t frequency,
                                       uint32_t tx_power_dbm,
                                       const unsigned char* mac) {
    int err;
    if (createInterface(AP_INTERFACE_NAME, NL80211_IFTYPE_AP, mac, phy_index) < 0) {
        Logger::log(error) << "Failed to create AP mode interface\n";
        return;
    }

    if (setInterfaceStatus(AP_INTERFACE_NAME, true) < 0) {
        Logger::log(error) << "Failed to set interface to up\n";
        return;
    };

    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    while ((err = setInterfaceFrequency(MONITOR_INTERFACE_NAME, frequency,
                                        Arguments::arguments.bandwidth.c_str())) < 0) {
        Logger::log(error) << "Failed to set frequency (" << err << ")\n";
        rfkill_unblock();
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    // TODO: fix tx power setting for AP interface, for now this will not loop...
    while ((err = setInterfaceTxPower(AP_INTERFACE_NAME, tx_power_dbm)) > 0) {
        Logger::log(error) << "Failed to set TX power(" << err << ")\n";
        rfkill_unblock();
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    };
}

uint16_t WiFIController::chanModeToWidth(struct ChanMode& chanMode) {
    switch (chanMode.width) {
        case NL80211_CHAN_WIDTH_20:
            return 20;
        case NL80211_CHAN_WIDTH_40:
            return 40;
        case NL80211_CHAN_WIDTH_80:
            return 80;
        case NL80211_CHAN_WIDTH_160:
            return 160;
        case NL80211_CHAN_WIDTH_320:
            return 320;
        default:
            break;
    }
    return 0;
}

ChanMode WiFIController::getChanMode(const char* width) {
    static const struct ChanMode chanMode[] = {
        {.name = "20",
         .width = NL80211_CHAN_WIDTH_20,
         .freq1_diff = 0,
         .chantype = NL80211_CHAN_HT20},
        {.name = "40",
         .width = NL80211_CHAN_WIDTH_40,
         .freq1_diff = 10,
         .chantype = NL80211_CHAN_HT40PLUS},
        {.name = "HT40-",
         .width = NL80211_CHAN_WIDTH_40,
         .freq1_diff = -10,
         .chantype = NL80211_CHAN_HT40MINUS},
        {.name = "NOHT",
         .width = NL80211_CHAN_WIDTH_20_NOHT,
         .freq1_diff = 0,
         .chantype = NL80211_CHAN_NO_HT},
        {.name = "5MHz", .width = NL80211_CHAN_WIDTH_5, .freq1_diff = 0, .chantype = -1},
        {.name = "10MHz", .width = NL80211_CHAN_WIDTH_10, .freq1_diff = 0, .chantype = -1},
        {.name = "80", .width = NL80211_CHAN_WIDTH_80, .freq1_diff = 0, .chantype = -1},
        {.name = "160", .width = NL80211_CHAN_WIDTH_160, .freq1_diff = 0, .chantype = -1},
        {.name = "320MHz", .width = NL80211_CHAN_WIDTH_320, .freq1_diff = 0, .chantype = -1},
        {.name = "1MHz", .width = NL80211_CHAN_WIDTH_1, .freq1_diff = 0, .chantype = -1},
        {.name = "2MHz", .width = NL80211_CHAN_WIDTH_2, .freq1_diff = 0, .chantype = -1},
        {.name = "4MHz", .width = NL80211_CHAN_WIDTH_4, .freq1_diff = 0, .chantype = -1},
        {.name = "8MHz", .width = NL80211_CHAN_WIDTH_8, .freq1_diff = 0, .chantype = -1},
        {.name = "16MHz", .width = NL80211_CHAN_WIDTH_16, .freq1_diff = 0, .chantype = -1},
    };

    struct ChanMode selectedChanMode = {};

    for (unsigned int i = 0; i < ARRAY_SIZE(chanMode); i++) {
        if (strcasecmp(chanMode[i].name, width) == 0) {
            selectedChanMode = chanMode[i];
            break;
        }
    }

    return selectedChanMode;
}

int WiFIController::getCf1(const struct ChanMode* chanmode, unsigned long freq) {
    unsigned int cf1 = freq, j;
    unsigned int bw80[] = {5180, 5260, 5500, 5580, 5660, 5745, 5955, 6035, 6115, 6195,
                           6275, 6355, 6435, 6515, 6595, 6675, 6755, 6835, 6195, 6995};
    unsigned int bw160[] = {5180, 5500, 5955, 6115, 6275, 6435, 6595, 6755, 6915};
    /* based on 11be D2 E.1 Country information and operating classes */
    unsigned int bw320[] = {5955, 6115, 6275, 6435, 6595, 6755};

    switch (chanmode->width) {
        case NL80211_CHAN_WIDTH_80:
            /* setup center_freq1 */
            for (j = 0; j < ARRAY_SIZE(bw80); j++) {
                if (freq >= bw80[j] && freq < bw80[j] + 80)
                    break;
            }

            if (j == ARRAY_SIZE(bw80))
                break;

            cf1 = bw80[j] + 30;
            break;
        case NL80211_CHAN_WIDTH_160:
            /* setup center_freq1 */
            for (j = 0; j < ARRAY_SIZE(bw160); j++) {
                if (freq >= bw160[j] && freq < bw160[j] + 160)
                    break;
            }

            if (j == ARRAY_SIZE(bw160))
                break;

            cf1 = bw160[j] + 70;
            break;
        case NL80211_CHAN_WIDTH_320:
            /* setup center_freq1 */
            for (j = 0; j < ARRAY_SIZE(bw320); j++) {
                if (freq >= bw320[j] && freq < bw320[j] + 160)
                    break;
            }

            if (j == ARRAY_SIZE(bw320))
                break;

            cf1 = bw320[j] + 150;
            break;
        default:
            cf1 = freq + chanmode->freq1_diff;
            break;
    }

    return cf1;
}

std::string WiFIController::mac_n2a(const unsigned char* arg) {
    int i, l;
    char mac_addr[20];

    l = 0;
    for (i = 0; i < ETH_ALEN; i++) {
        if (i == 0) {
            sprintf(mac_addr + l, "%02x", arg[i]);
            l += 2;
        } else {
            sprintf(mac_addr + l, ":%02x", arg[i]);
            l += 3;
        }
    }
    std::string ret = mac_addr;
    return ret;
}

bool WiFIController::mac_a2n(const std::string& mac, unsigned char* out) {
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F')
            return 10 + (c - 'A');
        return -1;
    };

    int hi = -1;          // high nibble (or -1 if expecting a high nibble)
    std::size_t idx = 0;  // number of bytes written

    for (char c : mac) {
        // Skip common separators
        if (c == ':' || c == '-' || c == ' ' || c == '\t')
            continue;

        int v = hexval(c);
        if (v < 0)
            return false;  // non-hex character

        if (hi < 0) {
            hi = v;  // store high nibble
        } else {
            if (idx >= ETH_ALEN)
                return false;  // too many hex digits
            out[idx++] = static_cast<unsigned char>((hi << 4) | v);
            hi = -1;  // reset for next byte
        }
    }

    // Must end on a full byte and have exactly 6 bytes
    return (hi == -1) && (idx == ETH_ALEN);
}

int WiFIController::frequencyToChannel(int freq) {
    if (freq < 1000)
        return 0;
    /* see 802.11-2007 17.3.8.3.2 and Annex J */
    if (freq == 2484)
        return 14;
    /* see 802.11ax D6.1 27.3.23.2 and Annex E */
    else if (freq == 5935)
        return 2;
    else if (freq < 2484)
        return (freq - 2407) / 5;
    else if (freq >= 4910 && freq <= 4980)
        return (freq - 4000) / 5;
    else if (freq < 5950)
        return (freq - 5000) / 5;
    else if (freq <= 45000) /* DMG band lower limit */
        /* see 802.11ax D6.1 27.3.23.2 */
        return (freq - 5950) / 5;
    else if (freq >= 58320 && freq <= 70200)
        return (freq - 56160) / 2160;
    else
        return 0;
}
