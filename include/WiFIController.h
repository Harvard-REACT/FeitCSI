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

#ifndef WIFI_CONTROLLER_H
#define WIFI_CONTROLLER_H

/* #define CONFIG_LIBNL30 // fix error compatibility iw
#include <iw/iw.h>
#include <iw/nl80211.h> */
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <netlink/msg.h>
#include "Netlink.h"

#include <optional>
#include <string>
#include <unordered_map>

#define ARRAY_SIZE(ar) (sizeof(ar) / sizeof(ar[0]))

struct InterfaceInfo {
    std::string ifName;
    nl80211_iftype ifType;
    uint32_t ifIndex;
    uint32_t wiphy;
    uint64_t wdev;
    std::string mac;

    std::string ssid;
    uint32_t freq;
    int channel;
    int channelWidth;
    int centerFreq1;
    int centerFreq2;
    int channelType;
    int32_t txdBm;
};

class InterfaceInfoBuilder {
   public:
    std::optional<std::string> interfaceName() const { return this->_interfaceName; };
    std::optional<nl80211_iftype> interfaceType() const { return this->_interfaceType; };
    std::optional<uint32_t> interfaceIndex() const { return this->_interfaceIndex; };
    std::optional<uint32_t> phyIndex() const { return this->_phyIndex; };
    std::optional<uint32_t> wdevIndex() const { return this->_wdevIndex; };
    std::optional<std::string> mac() const { return this->_macAddress; };
    std::optional<uint32_t> frequency() const { return this->_frequency; };
    std::optional<int32_t> txPowerDbm() const { return this->_tx_dbm; };

    InterfaceInfoBuilder& interfaceName(const std::string& interfaceName) {
        this->_interfaceName = interfaceName;
        return *this;
    };

    InterfaceInfoBuilder& interfaceType(const nl80211_iftype interfaceType) {
        this->_interfaceType = interfaceType;
        return *this;
    };

    InterfaceInfoBuilder& interfaceIndex(const uint32_t interfaceIndex) {
        this->_interfaceIndex = interfaceIndex;
        return *this;
    };

    InterfaceInfoBuilder& phyIndex(const uint32_t phyIndex) {
        this->_phyIndex = phyIndex;
        return *this;
    };

    InterfaceInfoBuilder& wdevIndex(const uint32_t wdevIndex) {
        this->_wdevIndex = wdevIndex;
        return *this;
    };

    InterfaceInfoBuilder& mac(const std::string& macAddress) {
        this->_macAddress = macAddress;
        return *this;
    };

    InterfaceInfoBuilder& frequency(const uint32_t frequency) {
        this->_frequency = frequency;
        return *this;
    };

    InterfaceInfoBuilder& txPowerDbm(const int32_t tx_dbm) {
        this->_tx_dbm = tx_dbm;
        return *this;
    };

    std::optional<InterfaceInfo> build() const {
        InterfaceInfo info;
        info.ifName = this->_interfaceName.value_or("Unnamed/non-netdev interface");
        info.ifType = this->_interfaceType.value_or(NL80211_IFTYPE_UNSPECIFIED);
        info.ifIndex = this->_interfaceIndex.value_or(0);
        info.wiphy = this->_phyIndex.value_or(0);
        info.wdev = this->_wdevIndex.value_or(0);
        info.mac = this->_macAddress.value_or("");
        info.freq = this->_frequency.value_or(0);
        info.txdBm = this->_tx_dbm.value_or(0);

        return info;
    }

   private:
    std::optional<std::string> _interfaceName;
    std::optional<nl80211_iftype> _interfaceType;
    std::optional<uint32_t> _interfaceIndex;
    std::optional<uint32_t> _phyIndex;
    std::optional<uint32_t> _wdevIndex;
    std::optional<std::string> _macAddress;
    std::optional<uint32_t> _frequency;
    std::optional<int32_t> _tx_dbm;
};

struct ChanMode {
    const char* name;
    unsigned int width;
    int freq1_diff;
    int chantype; /* for older kernel */
};

class WiFIController : public Netlink {
   public:
    /**
     * Request the configuration of all interfaces from the kernel. The requested information will
     * be stored in the `interfaces` member variable on this object.
     */
    void getAllInterfaces();

    /**
     * Request the configuration of an interface from the kernel. The requested information will be
     * stored in the `interfaces` member variable on this object.
     *
     * Parameters:
     *  interfaceName - Interface name to get information for a specific interface.
     *
     * Returns:
     *  The retreived interface information
     */
    [[nodiscard]] std::optional<InterfaceInfo> getInterfaceInfo(const std::string interfaceName);

    /**
     * Request the configuration of an interface from the kernel. The requested information will be
     * stored in the `interfaces` member variable on this object.
     *
     * Parameters:
     *  interfaceIndex - Interface index to get information for a specific interface.
     *
     * Returns:
     *  The retreived interface information
     */
    [[nodiscard]] std::optional<InterfaceInfo> getInterfaceInfo(uint32_t interfaceIndex);

    /**
     * Sets the transmit power of the interface with the given name to `power_dbm` dBm.
     * The corresponding interface information is automatically updated.
     *
     * Parameters:
     *  interfaceName - The name of the interface to set the power of
     *  power_dbm     - The transmit power to set the interface to in dBm
     *
     * Returns:
     *  0 on success, -1 on failure
     */
    [[nodiscard]] int setInterfaceTxPower(const std::string interfaceName, int32_t power_dbm);

    /**
     * Sets the transmit power of the interface with the given index to `power_dbm` dBm.
     *
     *
     * Parameters:
     *  interfaceIndex - The index of the interface to set the power of
     *  power_dbm      - The transmit power to set the interface to in dBm
     *
     * Returns:
     *  0 on success, -1 on failure
     */
    [[nodiscard]] int setInterfaceTxPower(uint32_t interfaceIndex, int32_t power_dbm);

    /**
     * Sets the frequency of the interface with the given name.
     *
     * Parameters:
     *  interfaceName - The name of the interface to set the frequency of
     *  frequency     - The frequency to set the interface to in mHz
     *  bandwidth     - The bandwidth to set the frequency to
     *
     * Returns:
     *  0 on success, -1 on failure
     */
    [[nodiscard]] int setInterfaceFrequency(const std::string interfaceName,
                                            uint32_t freq,
                                            const std::string bw);

    /**
     * Sets the frequency of the interface with the given index.
     *
     * Parameters:
     *  interfaceIndex - The index of the interface to set the frequency of
     *  frequency     - The frequency to set the interface to in ...
     *  bandwidth     - The bandwidth to set the frequency to
     *
     * Returns:
     *  0 on success, -1 on failure
     */
    [[nodiscard]] int setInterfaceFrequency(uint32_t interfaceIndex,
                                            uint16_t freq,
                                            const std::string bw);

    int abortScan(const std::string interfaceName);

    /**
     * Creates a new network device on the given phy driver.
     *
     * Parameters:
     *  interface_name - The name of the new interface
     *  type           - The mode the new interface should be configured in
     *  phyIndex       - The (kernel) index of the phy to configure the interface on
     */
    [[nodiscard]] int createInterface(const std::string interface_name,
                                      const nl80211_iftype type,
                                      const unsigned char* mac,
                                      uint32_t phyIndex);

    void deleteInterface(const std::string name);

    void deleteInterface(uint32_t interfaceIndex);

    /**
     * Sets the status of the given interface to up or down.
     * Parameters:
     *  interfaceName - The name of the interface to set the status of
     *  up            - true to bring the interface up, false to bring it down
     *
     * Returns:
     *  0         on success
     *  -ENOMEM   if the link cannot be alloc'ed
     *  -ENOTCONN if the rnl_socket is not initialized
     */
    [[nodiscard]] int setInterfaceStatus(const std::string ifName, bool up);

    void createMonitorInterface(uint32_t phy_index,
                                uint32_t frequency,
                                uint32_t tx_power_dbm,
                                const unsigned char* mac);
    void createApInterface(uint32_t phy_index,
                           uint32_t frequency,
                           uint32_t tx_power_dbm,
                           const unsigned char* mac);

    static ChanMode getChanMode(const char* width);
    static uint16_t chanModeToWidth(ChanMode& chanMode);

    /* Maps interface names to the corresponding information */
    std::unordered_map<std::string, InterfaceInfo> interfaces;

    std::string mac_n2a(const unsigned char* arg);

    bool mac_a2n(const std::string& mac, unsigned char* out);

   private:
    int frequencyToChannel(int freq);

    /**
     * Callback to process all discovered interface configurations from `getInterfaceInfo`
     * This should not be called directly, but rather automatically through a `nl_cb`.
     *
     * Parameters:
     *  msg - The Netlink message containing the interface configuration
     *  arg - Other arguments passed into the callback.
     *        This should contain a pointer to the WifiController instance that
     *        initiated the call.
     */
    static int getInterfaceInfoHandler(nl_msg* msg, void* arg);

    static int getInterfaceInfoTxPowerHandler(nl_msg* msg, void* arg);

    /**
     * Callback to set the transmit power of an interface
     *
     * Parameters:
     *  msg - The Netlink message to add the associated power attributes
     *  arg - Other arguments passed into the callback.
     *        this should contain a pointer to the transmit power level in dBm
     */
    static int setTxPowerHandler(nl80211_state* state, nl_msg* msg, void* arg);

    /**
     * Callback to create a new device (interface) on a phy
     *
     * Parameters:
     *  msg  - The Netlink message to add the associated device attributes
     *  type - The mode the new interface should be configured in
     *  arg  - Other arguments passed into the callback.
     *         This should be an array whose first element is a null-terminated string
     *         with the device name and whose second argument is the interface info
     */
    static int createInterfaceHandler(nl80211_state* state, nl_msg* msg, void* arg);

    /**
     * Callback to set the frequency of an interface
     *
     * Parameters:
     *  msg - The Netlink message to add the associated frequency attributes
     *  arg - Other arguments passed into the callback.
     *        This should be an array whose first element is a pointer to the frequency
     *        and whose second argument is a null terminated string corresponding to the
     *        bandwidth
     */
    static int setFrequencyHandler(nl80211_state* state, nl_msg* msg, void* arg);

    static int getCf1(const ChanMode* chanmode, unsigned long freq);
};

#endif