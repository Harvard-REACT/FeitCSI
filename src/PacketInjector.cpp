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

#include "PacketInjector.h"

#include <cstring>
#include <mutex>

#include "Arguments.h"
#include "Logger.h"
#include "main.h"  // for MONITOR_INTERFACE_NAME + rate flags (as in your existing code)

// NOTE: We intentionally keep a single pcap handle because the header only supports one.
// If you need per-interface injection, that requires a header change (map of handles).

#define SPATIAL_STREAM 16

namespace {

static inline void put_le16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v & 0xff);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xff);
}

static inline void put_le32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xff);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xff);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xff);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

static inline size_t align_to(size_t off, size_t a) {
    return (off + (a - 1)) & ~(a - 1);
}

struct RadiotapBuilder {
    uint8_t* buf;
    size_t cap;
    size_t off;        // current write offset
    uint32_t present;  // first present word only (no EXT used here)

    explicit RadiotapBuilder(uint8_t* b, size_t c) : buf(b), cap(c), off(8), present(0) {
        if (cap < 8)
            off = cap;
    }

    bool put_u8(int bit, uint8_t v) {
        present |= (1u << bit);
        if (off + 1 > cap)
            return false;
        buf[off++] = v;
        return true;
    }

    bool put_u16(int bit, uint16_t v) {
        present |= (1u << bit);
        off = align_to(off, 2);
        if (off + 2 > cap)
            return false;
        put_le16(buf + off, v);
        off += 2;
        return true;
    }

    bool put_bytes_aligned(int bit, const void* p, size_t n, size_t align) {
        present |= (1u << bit);
        off = align_to(off, align);
        if (off + n > cap)
            return false;
        std::memcpy(buf + off, p, n);
        off += n;
        return true;
    }

    size_t finish() {
        if (cap < 8)
            return 0;
        buf[0] = 0x00;                                  // it_version
        buf[1] = 0x00;                                  // it_pad
        put_le16(buf + 2, static_cast<uint16_t>(off));  // it_len
        put_le32(buf + 4, present);                     // it_present
        return off;
    }
};

// 24-byte 802.11 data header (ToDS=0, FromDS=0)
static size_t build_ieee80211_data_hdr(uint8_t* out,
                                       size_t cap,
                                       const std::array<uint8_t, 6>& addr1_ra_da,
                                       const std::array<uint8_t, 6>& addr2_ta_sa,
                                       const std::array<uint8_t, 6>& addr3_bssid) {
    if (cap < 24)
        return 0;

    // Data frame, subtype 0, ToDS=0, FromDS=0 => 0x0008 LE
    out[0] = 0x08;
    out[1] = 0x00;

    out[2] = 0x00;
    out[3] = 0x00;  // duration

    std::memcpy(out + 4, addr1_ra_da.data(), 6);
    std::memcpy(out + 10, addr2_ta_sa.data(), 6);
    std::memcpy(out + 16, addr3_bssid.data(), 6);

    out[22] = 0x00;
    out[23] = 0x00;  // seq ctrl
    return 24;
}

static uint8_t ofdm_rate_500kbps_from_mcs(uint8_t mcs) {
    // 0..7 -> 6,9,12,18,24,36,48,54 Mbps
    static const uint8_t rates_500[] = {12, 18, 24, 36, 48, 72, 96, 108};
    if (mcs < 8)
        return rates_500[mcs];
    return 12;  // 6 Mbps fallback
}

static bool radiotap_from_rateNFlags(uint8_t* out,
                                     size_t cap,
                                     uint32_t rateNFlags,
                                     const Args& a,
                                     size_t& rt_len_out) {
    RadiotapBuilder rt(out, cap);

    // FLAGS (bit 1) and TX_FLAGS (bit 15) help capture decode
    if (!rt.put_u8(IEEE80211_RADIOTAP_FLAGS, 0x00))
        return false;
    if (!rt.put_u16(IEEE80211_RADIOTAP_TX_FLAGS, 0x0000))
        return false;

    if (a.format == "NOHT") {
        const uint8_t mcs = static_cast<uint8_t>(rateNFlags & RATE_LEGACY_RATE_MSK);
        const uint8_t rate = ofdm_rate_500kbps_from_mcs(mcs);
        if (!rt.put_u8(IEEE80211_RADIOTAP_RATE, rate))
            return false;

    } else if (a.format == "HT") {
        // radiotap MCS: {known, flags, mcs}
        uint8_t known = 0;
        uint8_t flags = 0;

        known |= 1u << 0;  // BW known
        if (rateNFlags & RATE_MCS_CHAN_WIDTH_40)
            flags |= 1u << 0;  // BW 40

        known |= 1u << 2;  // GI known
        if (rateNFlags & RATE_MCS_SGI_MSK)
            flags |= 1u << 2;  // SGI

        known |= 1u << 3;  // FEC known
        if (rateNFlags & RATE_MCS_LDPC_MSK)
            flags |= 1u << 4;  // LDPC (wireshark expects bit4 here)

        const uint8_t mcs = static_cast<uint8_t>(rateNFlags & RATE_HT_MCS_CODE_MSK);
        uint8_t mcs_field[3] = {known, flags, mcs};

        if (!rt.put_bytes_aligned(IEEE80211_RADIOTAP_MCS, mcs_field, sizeof(mcs_field), 1))
            return false;

    } else if (a.format == "VHT") {
        // radiotap VHT: 12 bytes
        uint8_t vht[12];
        std::memset(vht, 0, sizeof(vht));

        uint16_t known = 0;
        uint8_t flags = 0;
        uint8_t bw = 0;

        known |= 1u << 6;  // BW known
        if (rateNFlags & RATE_MCS_CHAN_WIDTH_160)
            bw = 11;
        else if (rateNFlags & RATE_MCS_CHAN_WIDTH_80)
            bw = 4;
        else if (rateNFlags & RATE_MCS_CHAN_WIDTH_40)
            bw = 1;
        else
            bw = 0;

        known |= 1u << 2;  // GI known
        if (rateNFlags & RATE_MCS_SGI_MSK)
            flags |= 1u << 2;

        const uint8_t coding = (rateNFlags & RATE_MCS_LDPC_MSK) ? 1 : 0;

        const uint8_t mcs = static_cast<uint8_t>(rateNFlags & RATE_MCS_CODE_MSK);
        const uint8_t nss = static_cast<uint8_t>(a.spatialStreams);
        const uint8_t mcs_nss = static_cast<uint8_t>(((nss & 0x0f) << 4) | (mcs & 0x0f));

        put_le16(vht + 0, known);
        vht[2] = flags;
        vht[3] = bw;
        vht[4] = mcs_nss;  // user0
        vht[8] = coding;

        if (!rt.put_bytes_aligned(IEEE80211_RADIOTAP_VHT, vht, sizeof(vht), 2))
            return false;

    } else if (a.format == "HESU") {
        // radiotap HE: 12 bytes (6x u16)
        uint16_t he[6];
        std::memset(he, 0, sizeof(he));

        he[0] =
            static_cast<uint16_t>((rateNFlags & RATE_MCS_HE_GI_LTF_MSK) >> RATE_MCS_HE_GI_LTF_POS);

        const uint8_t mcs = static_cast<uint8_t>(rateNFlags & RATE_MCS_CODE_MSK);
        const uint8_t nss = static_cast<uint8_t>(a.spatialStreams);
        he[1] = static_cast<uint16_t>((nss << 8) | mcs);

        if (!rt.put_bytes_aligned(IEEE80211_RADIOTAP_HE, he, sizeof(he), 2))
            return false;
    }

    rt_len_out = rt.finish();
    return rt_len_out != 0;
}

}  // namespace

void PacketInjector::inject(const std::array<uint8_t, 6>& src) {
    if (Arguments::arguments.verbose) {
        Logger::log(info) << "Injecting " << Arguments::arguments.format << "\n";
    }

    if (Arguments::arguments.format == "NOHT") {
        this->injectNoHT(src);
    } else if (Arguments::arguments.format == "HT") {
        this->injectHT(src);
    } else if (Arguments::arguments.format == "VHT") {
        this->injectVHT(src);
    } else if (Arguments::arguments.format == "HESU") {
        this->injectHE(src);
    }
}

void PacketInjector::injectNoHT(const std::array<uint8_t, 6>& src) {
    uint8_t mcs = 0;
    if (RATE_LEGACY_RATE_MSK >= Arguments::arguments.mcs) {
        mcs = RATE_LEGACY_RATE_MSK & Arguments::arguments.mcs;
    }
    uint32_t rateNFlags = RATE_MCS_LEGACY_OFDM_MSK | mcs | Arguments::arguments.antenna;
    this->send(rateNFlags, src);
}

void PacketInjector::injectHT(const std::array<uint8_t, 6>& src) {
    uint8_t mcs = 0;
    if (RATE_HT_MCS_CODE_MSK >= Arguments::arguments.mcs) {
        mcs = RATE_HT_MCS_CODE_MSK & Arguments::arguments.mcs;
    }
    uint32_t rateNFlags = RATE_MCS_HT_MSK | mcs | Arguments::arguments.antenna |
                          (Arguments::arguments.channelWidth == 40 ? RATE_MCS_CHAN_WIDTH_40 : 0) |
                          (Arguments::arguments.spatialStreams == 2 ? SPATIAL_STREAM : 0) |
                          (Arguments::arguments.spatialStreams == 2 ? RATE_MCS_ANT_AB_MSK : 0) |
                          (Arguments::arguments.guardInterval == 400 ? RATE_MCS_SGI_MSK : 0) |
                          (Arguments::arguments.coding == "LDPC" ? RATE_MCS_LDPC_MSK : 0);
    this->send(rateNFlags, src);
}

void PacketInjector::injectVHT(const std::array<uint8_t, 6>& src) {
    uint8_t mcs = 0;
    if (RATE_MCS_CODE_MSK >= Arguments::arguments.mcs) {
        mcs = RATE_MCS_CODE_MSK & Arguments::arguments.mcs;
    }
    uint32_t rateNFlags = RATE_MCS_VHT_MSK | mcs | Arguments::arguments.antenna |
                          (Arguments::arguments.channelWidth == 40 ? RATE_MCS_CHAN_WIDTH_40 : 0) |
                          (Arguments::arguments.channelWidth == 80 ? RATE_MCS_CHAN_WIDTH_80 : 0) |
                          (Arguments::arguments.channelWidth == 160 ? RATE_MCS_CHAN_WIDTH_160 : 0) |
                          (Arguments::arguments.spatialStreams == 2 ? SPATIAL_STREAM : 0) |
                          (Arguments::arguments.spatialStreams == 2 ? RATE_MCS_ANT_AB_MSK : 0) |
                          (Arguments::arguments.guardInterval == 400 ? RATE_MCS_SGI_MSK : 0) |
                          (Arguments::arguments.coding == "LDPC" ? RATE_MCS_LDPC_MSK : 0);
    this->send(rateNFlags, src);
}

void PacketInjector::injectHE(const std::array<uint8_t, 6>& src) {
    uint8_t mcs = 0;
    if (RATE_MCS_CODE_MSK >= Arguments::arguments.mcs) {
        mcs = RATE_MCS_CODE_MSK & Arguments::arguments.mcs;
    }

    uint32_t ltf = 1;
    if (Arguments::arguments.ltf == "2xLTF+0.8")
        ltf = 1;
    else if (Arguments::arguments.ltf == "2xLTF+1.6")
        ltf = 2;
    else if (Arguments::arguments.ltf == "4xLTF+3.2")
        ltf = 3;
    else if (Arguments::arguments.ltf == "4xLTF+0.8")
        ltf = 4;

    ltf = (ltf << RATE_MCS_HE_GI_LTF_POS) & RATE_MCS_HE_GI_LTF_MSK;

    uint32_t rateNFlags = RATE_MCS_HE_MSK | RATE_MCS_LDPC_MSK | mcs | Arguments::arguments.antenna |
                          ltf |
                          (Arguments::arguments.channelWidth == 40 ? RATE_MCS_CHAN_WIDTH_40 : 0) |
                          (Arguments::arguments.channelWidth == 80 ? RATE_MCS_CHAN_WIDTH_80 : 0) |
                          (Arguments::arguments.channelWidth == 160 ? RATE_MCS_CHAN_WIDTH_160 : 0) |
                          (Arguments::arguments.spatialStreams == 2 ? SPATIAL_STREAM : 0) |
                          (Arguments::arguments.spatialStreams == 2 ? RATE_MCS_ANT_AB_MSK : 0);

    this->send(rateNFlags, src);
}

void PacketInjector::send(uint32_t rateNFlags, const std::array<uint8_t, 6>& src) {
    // Minimal thread-safety without changing header:
    // - ppcap open + pcap_inject are guarded so two threads can't race and corrupt libpcap state.
    static std::mutex inject_mu;
    std::lock_guard<std::mutex> lk(inject_mu);

    // Basic test frame: broadcast destination + broadcast BSSID
    const std::array<uint8_t, 6> bcast = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const std::array<uint8_t, 6> dst = bcast;
    const std::array<uint8_t, 6> bssid = bcast;

    uint8_t frame[2048];
    size_t off = 0;

    // radiotap
    size_t rt_len = 0;
    if (!radiotap_from_rateNFlags(frame + off, sizeof(frame) - off, rateNFlags,
                                  Arguments::arguments, rt_len)) {
        Logger::log(error) << "Failed to build radiotap\n";
        return;
    }
    off += rt_len;

    // 802.11 header
    const size_t hdr_len =
        build_ieee80211_data_hdr(frame + off, sizeof(frame) - off, dst, src, bssid);
    if (!hdr_len) {
        Logger::log(error) << "Failed to build 802.11 header\n";
        return;
    }
    off += hdr_len;

    // payload
    static const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef, 0x46, 0x65,
                                      0x69, 0x74, 0x43, 0x53, 0x49};
    if (off + sizeof(payload) > sizeof(frame)) {
        Logger::log(error) << "Frame too large\n";
        return;
    }
    std::memcpy(frame + off, payload, sizeof(payload));
    off += sizeof(payload);

    // Open pcap once, reuse
    if (!ppcap) {
        char errbuf[PCAP_ERRBUF_SIZE]{};
        const char* ifname = MONITOR_INTERFACE_NAME;

        ppcap = pcap_open_live(ifname, 2048, 1, 20, errbuf);
        if (!ppcap) {
            Logger::log(error) << "pcap_open_live(" << ifname << ") failed: " << errbuf << "\n";
            return;
        }
    }

    const int r = pcap_inject(ppcap, frame, static_cast<int>(off));
    if (r < 0) {
        Logger::log(error) << "pcap_inject failed: " << pcap_geterr(ppcap) << "\n";
        return;
    }
    if (r != static_cast<int>(off)) {
        Logger::log(warning) << "pcap_inject wrote " << r << " bytes, expected " << off << "\n";
        return;
    }

    if (Arguments::arguments.verbose) {
        Logger::log(info) << "Injected " << off << " bytes; format=" << Arguments::arguments.format
                          << " rateNFlags=0x" << std::hex << rateNFlags << std::dec << "\n";
    }
}
