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

#ifndef ARGUMENTS_PARSER_H
#define ARGUMENTS_PARSER_H

#include <argp.h>
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "main.h"
#include "rs.h"

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

struct Args {
    bool strict = false;
    bool verbose = false;
    uint16_t frequency = 2412;
    bool gui = false;
    bool udpSocket = false;
    bool plot = false;

    std::string bandwidth = "20";
    std::string outputFile;

    uint8_t mcs = 0;
    uint16_t channelWidth = 20;
    uint8_t spatialStreams = 1;
    uint8_t txPower = 10;
    uint32_t antenna = RATE_MCS_ANT_A_MSK;
    uint16_t guardInterval = 400;

    uint32_t injectDelay = 100000;
    uint32_t injectRepeat = 0;

    uint32_t phy = 0;
    std::string coding = "LDPC";
    std::string format = "HT";

    bool inject = false;
    bool measure = true;
    std::string mode = "measure";
    std::string ltf = "1xLTF+0.8";
    uint32_t modeDelay = 3000;

    bool ftm = false;
    bool ftmResponder = false;
    bool ftmAsap = false;
    uint8_t ftmBurstExp = 0;
    uint8_t ftmPerBurst = 0;
    uint16_t ftmBurstPeriod = 0;
    uint8_t ftmBurstDuration = 0;

    std::vector<std::array<uint8_t, ETH_ALEN>> macs = {
        std::array<uint8_t, ETH_ALEN>{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    };

    std::array<uint8_t, ETH_ALEN> ftmTargetMac{};  // zeroed
    std::string inputFile;

    std::map<enum processor, bool> processors;
};

class Arguments {
   public:
    static Args arguments;
    static void parse(int argc, char* argv[]);
};

#endif