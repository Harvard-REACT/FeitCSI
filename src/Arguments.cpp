/*
 * FeitCSI is the tool for extracting CSI information from supported intel NICs.
 * Copyright (C) 2024-2025 Miroslav Hutar.
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

#include "Arguments.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "WiFIController.h"

// If you want argp to show version, use a stable C string
// (avoid std::string static-init order pitfalls)
const char* argp_program_version = "FeitCSI " FEITCSI_VERSION;
const char* argp_program_bug_address = "https://github.com/KuskoSoft/FeitCSI/issues";

// --- Definition of the single global args object ---
Args Arguments::arguments{};

// --- argp docs ---
static char doc[] =
    "FeitCSI - the tool that enables CSI extraction and injection of IEEE 802.11 frames";
static char args_doc[] = "";

// --- helpers ---
static std::string trim_copy(const std::string& in) {
    size_t b = 0;
    while (b < in.size() && std::isspace(static_cast<unsigned char>(in[b])))
        b++;
    size_t e = in.size();
    while (e > b && std::isspace(static_cast<unsigned char>(in[e - 1])))
        e--;
    return in.substr(b, e - b);
}

static bool parse_one_mac(const char* s, std::array<uint8_t, ETH_ALEN>& out) {
    if (!s)
        return false;
    // Require exactly 6 bytes in xx:xx:xx:xx:xx:xx form
    int res = std::sscanf(s, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &out[0], &out[1], &out[2],
                          &out[3], &out[4], &out[5]);
    return res == ETH_ALEN;
}

static void add_macs_from_list_or_die(struct argp_state* state, Args& args, const char* arg) {
    if (!arg || *arg == '\0') {
        argp_failure(state, 1, 0, "Bad mac address (empty)");
        std::exit(ARGP_ERR_UNKNOWN);
    }

    // First time user specifies --mac, clear defaults exactly once.
    // We track this via argp_state->hook (a void* you can use).
    bool* user_specified_any_mac = static_cast<bool*>(state->hook);
    if (user_specified_any_mac && !*user_specified_any_mac) {
        args.macs.clear();
        *user_specified_any_mac = true;
    }

    std::string list(arg);
    size_t start = 0;
    while (start < list.size()) {
        size_t comma = list.find(',', start);
        std::string token =
            (comma == std::string::npos) ? list.substr(start) : list.substr(start, comma - start);
        token = trim_copy(token);

        if (token.empty()) {
            argp_failure(state, 1, 0, "Bad mac address (empty entry in list)");
            std::exit(ARGP_ERR_UNKNOWN);
        }

        std::array<uint8_t, ETH_ALEN> mac{};
        if (!parse_one_mac(token.c_str(), mac)) {
            argp_failure(state, 1, 0, "Bad mac address: %s", token.c_str());
            std::exit(ARGP_ERR_UNKNOWN);
        }

        args.macs.push_back(mac);

        if (comma == std::string::npos)
            break;
        start = comma + 1;
    }

    if (args.macs.empty()) {
        argp_failure(state, 1, 0, "No valid MAC addresses provided");
        std::exit(ARGP_ERR_UNKNOWN);
    }
}

// --- options ---
// Use 'M' for mac; avoid weird characters like '#'.
static struct argp_option options[] = {
    {"frequency", 'f', "FREQUENCY", 0, "Frequency to measure/inject CSI (MHz)"},
    {"channel-width", 'w', "CHANNELWIDTH", 0,
     "Channel width. Possible values [20|40|HT40-|80|160]"},
    {"output-file", 'o', "FILE", 0, "Output file where measurements should be stored."},
    {"mcs", 'm', "MCS", 0, "MCS index [0-11]"},
    {"format", 'r', "FORMAT", 0, "Data frame format [NOHT|HT|VHT|HESU]"},
    {"spatial-streams", 's', "SPATIALSTREAMS", 0, "Number of spatial streams [1|2]"},
    {"guard-interval", 'g', "GUARDINTERVAL", 0, "Guard interval [400|800]"},
    {"ltf", 'l', "LTF", 0, "HE LTF [1xLTF+0.8|2xLTF+0.8|2xLTF+1.6|4xLTF+3.2|4xLTF+0.8]"},
    {"coding", 'c', "CODING", 0, "Coding scheme [LDPC|BCC]"},
    {"tx-power", 't', "TXPOWER", 0, "TX power in dBm [1-22]"},
    {"phy", '@', "PHY", 0, "PHY index to create the interface on"},
    {"antenna", 'a', "ANTENNA", 0, "Transmitting antenna: 1, 2, or 12 for both"},
    {"mode", 'i', "MODE", 0,
     "Mode [measure|inject|measureinject|ftm|ftmres|injectftmres|measureftm]"},
    {"inject-delay", 'd', "INJECTDELAY", 0, "Delay between injections (us)"},
    {"inject-repeat", 'j', "INJECTREPEAT", 0, "Number of injections (0=forever)"},
    {"verbose", 'v', 0, OPTION_ARG_OPTIONAL, "Verbose output"},
    {"plot", 'p', 0, OPTION_ARG_OPTIONAL, "Plot CSI data"},
    {"gui", 'x', 0, OPTION_ARG_OPTIONAL, "Run GUI"},
    {"udp-socket", 'u', 0, OPTION_ARG_OPTIONAL, "Listen to UDP"},
    {"ftm-asap", 'b', 0, OPTION_ARG_OPTIONAL, "FTM asap mode"},
    {"ftm-burst-exp", 'q', "FTMBURSTEXP", 0, "FTM burst exponent"},
    {"ftm-per-burst", 'e', "FTMPERBURST", 0, "FTM samples per burst"},
    {"ftm-burst-period", 'h', "FTMBURSTPERIOD", 0, "FTM burst period"},
    {"ftm-burst-duration", 'k', "FTMBURSTSDURATION", 0, "FTM burst duration"},
    {"ftm-mac", 'n', "FTMMAC", 0, "FTM target MAC address xx:xx:xx:xx:xx:xx"},
    {"mode-delay", 'y', "SWAPTIME", 0, "Delay in ms between paired modes"},
    {"strict", 'z', 0, OPTION_ARG_OPTIONAL, "Strict mode"},
    {"mac", 'M', "MAC[,MAC...]", 0,
     "Override NIC MAC(s). Repeatable: --mac aa:bb:... --mac 11:22:... "
     "or comma-separated: --mac aa:bb:...,11:22:..."},
    {0}};

// --- parser ---
static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    // We always parse into the one global object, but still take input for clarity.
    auto* args = static_cast<Args*>(state->input);
    if (!args)
        return ARGP_ERR_UNKNOWN;

    switch (key) {
        case ARGP_KEY_INIT: {
            // hook used to track whether user provided any --mac
            static bool user_specified_any_mac = false;
            user_specified_any_mac = false;
            state->hook = &user_specified_any_mac;
            return 0;
        }

        case 'v':
            args->verbose = true;
            return 0;
        case 'z':
            args->strict = true;
            return 0;
        case 'x':
            args->gui = true;
            return 0;
        case 'u':
            args->udpSocket = true;
            return 0;
        case 'p':
            args->plot = true;
            return 0;

        case 'i': {
            if (!arg) {
                argp_failure(state, 1, 0, "Mode is missing");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->mode.assign(arg);

            // reset related flags then set according to mode
            args->inject = false;
            args->measure = false;
            args->ftm = false;
            args->ftmResponder = false;

            if (args->mode == "measure") {
                args->measure = true;
            } else if (args->mode == "inject") {
                args->inject = true;
            } else if (args->mode == "measureinject") {
                args->measure = true;
                args->inject = true;
            } else if (args->mode == "measureftm") {
                args->measure = true;
                args->ftm = true;
            } else if (args->mode == "ftm") {
                args->ftm = true;
            } else if (args->mode == "ftmres") {
                args->ftmResponder = true;
            } else if (args->mode == "injectftmres") {
                args->inject = true;
                args->ftmResponder = true;
            } else {
                argp_failure(state, 1, 0,
                             "Bad mode. Possible values "
                             "[measure|inject|measureinject|ftm|ftmres|injectftmres|measureftm]");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            return 0;
        }

        case 'm': {
            int mcs = arg ? std::atoi(arg) : -1;
            if (mcs < 0 || mcs > 11) {
                argp_failure(state, 1, 0, "Bad MCS index. Possible values [0-11]");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->mcs = static_cast<uint8_t>(mcs);
            return 0;
        }

        case 'r': {
            if (!arg) {
                argp_failure(state, 1, 0, "Format is missing");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->format.assign(arg);
            if (args->format != "NOHT" && args->format != "HT" && args->format != "VHT" &&
                args->format != "HESU") {
                argp_failure(state, 1, 0, "Bad format. Possible values [NOHT|HT|VHT|HESU]");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            return 0;
        }

        case 'c': {
            if (!arg) {
                argp_failure(state, 1, 0, "Coding is missing");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->coding.assign(arg);
            if (args->coding != "LDPC" && args->coding != "BCC") {
                argp_failure(state, 1, 0, "Bad coding. Possible values [LDPC|BCC]");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            return 0;
        }

        case 'l': {
            if (!arg) {
                argp_failure(state, 1, 0, "LTF is missing");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->ltf.assign(arg);
            if (args->ltf != "1xLTF+0.8" && args->ltf != "2xLTF+0.8" && args->ltf != "2xLTF+1.6" &&
                args->ltf != "4xLTF+3.2" && args->ltf != "4xLTF+0.8") {
                argp_failure(state, 1, 0,
                             "Bad LTF. Possible values "
                             "[1xLTF+0.8|2xLTF+0.8|2xLTF+1.6|4xLTF+3.2|4xLTF+0.8]");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            return 0;
        }

        case 'y': {
            int v = arg ? std::atoi(arg) : 0;
            if (v <= 0) {
                argp_failure(state, 1, 0, "Mode delay must be > 0");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->modeDelay = static_cast<uint32_t>(v);
            return 0;
        }

        case 'g': {
            int gi = arg ? std::atoi(arg) : 0;
            if (gi != 400 && gi != 800) {
                argp_failure(state, 1, 0, "Bad guard interval. Possible values [400|800]");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->guardInterval = static_cast<uint16_t>(gi);
            return 0;
        }

        case 'd': {
            int v = arg ? std::atoi(arg) : 0;
            if (v <= 0) {
                argp_failure(state, 1, 0, "Inject delay must be > 0");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->injectDelay = static_cast<uint32_t>(v);
            return 0;
        }

        case 'j': {
            int v = arg ? std::atoi(arg) : -1;
            if (v < 0) {
                argp_failure(state, 1, 0, "Inject repeat must be >= 0");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->injectRepeat = static_cast<uint32_t>(v);
            return 0;
        }

        case 's': {
            int v = arg ? std::atoi(arg) : 0;
            if (v < 1 || v > 2) {
                argp_failure(state, 1, 0, "Bad spatial stream. Possible values [1|2]");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->spatialStreams = static_cast<uint8_t>(v);
            return 0;
        }

        case 't': {
            int v = arg ? std::atoi(arg) : 0;
            if (v < 1 || v > 22) {
                argp_failure(state, 1, 0, "Bad tx power. Possible values [1-22]");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->txPower = static_cast<uint8_t>(v);
            return 0;
        }

        case 'a': {
            int v = arg ? std::atoi(arg) : 0;
            if (v == 1)
                args->antenna = RATE_MCS_ANT_A_MSK;
            else if (v == 2)
                args->antenna = RATE_MCS_ANT_B_MSK;
            else if (v == 12)
                args->antenna = RATE_MCS_ANT_AB_MSK;
            else {
                argp_failure(state, 1, 0, "Bad antenna. Possible values 1, 2, or 12");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            return 0;
        }

        case 'f': {
            int v = arg ? std::atoi(arg) : 0;
            if (v <= 0) {
                argp_failure(state, 1, 0, "Frequency must be > 0");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->frequency = static_cast<uint16_t>(v);
            return 0;
        }

        case 'w': {
            if (!arg) {
                argp_failure(state, 1, 0, "Channel width is missing");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            ChanMode chMode = WiFIController::getChanMode(arg);
            if (chMode.width == 0) {
                argp_failure(state, 1, 0, "Bad bandwidth. Possible values [20|40|HT40-|80|160]");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->bandwidth = arg;
            args->channelWidth = WiFIController::chanModeToWidth(chMode);
            return 0;
        }

        case 'o':
            args->outputFile = arg ? arg : "";
            return 0;

        case 'b':
            args->ftmAsap = true;
            return 0;

        case 'q': {
            int v = arg ? std::atoi(arg) : 0;
            if (v <= 0) {
                argp_failure(state, 1, 0, "FTM burst exponent must be > 0");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->ftmBurstExp = static_cast<uint8_t>(v);
            return 0;
        }

        case 'e': {
            int v = arg ? std::atoi(arg) : 0;
            if (v <= 0) {
                argp_failure(state, 1, 0, "FTM per burst must be > 0");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->ftmPerBurst = static_cast<uint8_t>(v);
            return 0;
        }

        case 'h': {
            int v = arg ? std::atoi(arg) : 0;
            if (v <= 0) {
                argp_failure(state, 1, 0, "FTM burst period must be > 0");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->ftmBurstPeriod = static_cast<uint16_t>(v);
            return 0;
        }

        case 'k': {
            int v = arg ? std::atoi(arg) : 0;
            if (v <= 0) {
                argp_failure(state, 1, 0, "FTM burst duration must be > 0");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->ftmBurstDuration = static_cast<uint8_t>(v);
            return 0;
        }

        case 'M':
            add_macs_from_list_or_die(state, *args, arg);
            return 0;

        case 'n': {
            if (!arg) {
                argp_failure(state, 1, 0, "FTM target MAC missing");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            std::array<uint8_t, ETH_ALEN> mac{};
            if (!parse_one_mac(arg, mac)) {
                argp_failure(state, 1, 0, "FTM target MAC is not correct");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            args->ftmTargetMac = mac;
            return 0;
        }

        case ARGP_KEY_END: {
            if (args->frequency == 0 || args->bandwidth.empty()) {
                argp_failure(state, 1, 0, "Missing required args -f and -w");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            if (args->macs.empty()) {
                // If user cleared defaults and provided none, error (should already be handled)
                argp_failure(state, 1, 0, "No MACs configured");
                std::exit(ARGP_ERR_UNKNOWN);
            }
            return 0;
        }

        default:
            return ARGP_ERR_UNKNOWN;
    }
}

void Arguments::parse(int argc, char* argv[]) {
    static struct argp argp = {options, parse_opt, args_doc, doc};
    // Parse directly into the one global object.
    argp_parse(&argp, argc, argv, 0, nullptr, &Arguments::arguments);
}