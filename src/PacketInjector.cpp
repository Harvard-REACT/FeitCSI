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
#include <string.h>
#include <cstdint>
#include <cstring>
#include "Arguments.h"
#include "Logger.h"
#include "main.h"

#define SPATIAL_STREAM 16

uint8_t ieee80211Header[] = {0xe0, 0x80, 0x00, 0x00, 0x00, 0x16, 0xea, 0x12, 0x34, 0x56,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x98, 0x59, 0x7a, 0x8b,
                             0x34, 0x3b, 0x00, 0x00, 0x15, 0x03, 0x15, 0x20};

uint8_t ieee80211Body[] = {};

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

// Radiotap field sizes/alignments (common ones we use)
static inline size_t align_to(size_t off, size_t a) {
    return (off + (a - 1)) & ~(a - 1);
}

struct RadiotapBuilder {
    uint8_t* buf;
    size_t cap;
    size_t off;        // current write offset
    uint32_t present;  // first present word only (no EXT used here)

    explicit RadiotapBuilder(uint8_t* b, size_t c) : buf(b), cap(c), off(8), present(0) {
        // reserve 8 bytes for fixed header: version,pad,len,present
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

    // finalize: write header and return total length
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

// Build a standard 24-byte 802.11 data header (ToDS=0, FromDS=0)
static size_t build_ieee80211_data_hdr(uint8_t* out,
                                       size_t cap,
                                       const std::array<uint8_t, 6>& addr1_ra_da,
                                       const std::array<uint8_t, 6>& addr2_ta_sa,
                                       const std::array<uint8_t, 6>& addr3_bssid) {
    if (cap < 24)
        return 0;

    // Frame Control: Data subtype 0, ToDS=0, FromDS=0 => 0x0008 little-endian
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

// Map legacy OFDM index to radiotap RATE (500kbps units). If your "mcs" differs, adjust.
static uint8_t ofdm_rate_500kbps_from_mcs(uint8_t mcs) {
    // 0..7 -> 6,9,12,18,24,36,48,54 Mbps
    static const uint8_t rates_500[] = {12, 18, 24, 36, 48, 72, 96, 108};
    if (mcs < 8)
        return rates_500[mcs];
    return 12;  // fallback to 6Mbps
}

static bool radiotap_from_rateNFlags(uint8_t* out,
                                     size_t cap,
                                     uint32_t rateNFlags,
                                     const Args& a,
                                     size_t& rt_len_out) {
    RadiotapBuilder rt(out, cap);

    // Always include FLAGS (bit 1) and TX_FLAGS (bit 15) so capture is sane.
    // FLAGS=0, TX_FLAGS=0
    if (!rt.put_u8(IEEE80211_RADIOTAP_FLAGS, 0x00))
        return false;
    if (!rt.put_u16(IEEE80211_RADIOTAP_TX_FLAGS, 0x0000))
        return false;

    // Decide which radiotap PHY field to emit based on format / rateNFlags.
    // Prefer format string (since your code already chose HT/VHT/HE).
    if (a.format == "NOHT") {
        // Legacy rate: use IEEE80211_RADIOTAP_RATE (bit 2), 1 byte (500kbps units)
        const uint8_t mcs = static_cast<uint8_t>(rateNFlags & RATE_LEGACY_RATE_MSK);
        uint8_t rate = ofdm_rate_500kbps_from_mcs(mcs);
        if (!rt.put_u8(IEEE80211_RADIOTAP_RATE, rate))
            return false;

    } else if (a.format == "HT") {
        // IEEE80211_RADIOTAP_MCS (bit 19): 3 bytes {known, flags, mcs}
        // known bits (radiotap spec): 0=BW,1=MCS,2=GI,3=FEC,4=STBC,5=NESS,6=NESS_KNOWN
        uint8_t known = 0;
        uint8_t flags = 0;

        // BW
        known |= 1u << 0;
        if (rateNFlags & RATE_MCS_CHAN_WIDTH_40)
            flags |= 1u << 0;  // MCS_BW_40

        // GI
        known |= 1u << 2;
        if (rateNFlags & RATE_MCS_SGI_MSK)
            flags |= 1u << 2;  // MCS_SGI

        // FEC
        known |= 1u << 3;
        if (rateNFlags & RATE_MCS_LDPC_MSK)
            flags |= 1u << 4;  // MCS_FEC_LDPC (radiotap uses bit4)
        // Note: radiotap MCS flags differ per implementation; Wireshark expects LDPC at bit4.

        // (optional) STBC if you have a mask for it in rateNFlags; not shown in your code.

        uint8_t mcs = static_cast<uint8_t>(rateNFlags & RATE_HT_MCS_CODE_MSK);

        uint8_t mcs_field[3] = {known, flags, mcs};
        if (!rt.put_bytes_aligned(IEEE80211_RADIOTAP_MCS, mcs_field, sizeof(mcs_field), 1))
            return false;

    } else if (a.format == "VHT") {
        // IEEE80211_RADIOTAP_VHT (bit 21): 12 bytes
        // struct:
        //  u16 known; u8 flags; u8 bandwidth; u8 mcs_nss[4]; u8 coding; u8 group_id; u16
        //  partial_aid;
        uint8_t vht[12];
        std::memset(vht, 0, sizeof(vht));

        uint16_t known = 0;
        uint8_t flags = 0;
        uint8_t bw = 0;

        // known bits per radiotap vht spec:
        // 0=STBC,1=TXOP_PS,2=GI,3=SGI_NSYM_DIS,4=LDPC_EXTRA,5=BF,6=BW,7=GROUP_ID,8=PARTIAL_AID
        // We'll only set BW + GI (as SGI) + LDPC where possible.
        known |= 1u << 6;  // BW known
        if (rateNFlags & RATE_MCS_CHAN_WIDTH_160) {
            bw = 11;  // 160 MHz in radiotap VHT
        } else if (rateNFlags & RATE_MCS_CHAN_WIDTH_80) {
            bw = 4;  // 80 MHz
        } else if (rateNFlags & RATE_MCS_CHAN_WIDTH_40) {
            bw = 1;  // 40 MHz
        } else {
            bw = 0;  // 20 MHz
        }

        // GI: radiotap VHT uses flag bit 2 to indicate short GI
        known |= 1u << 2;
        if (rateNFlags & RATE_MCS_SGI_MSK)
            flags |= 1u << 2;

        // LDPC: radiotap VHT uses "coding" byte: 0 = BCC, 1 = LDPC
        uint8_t coding = (rateNFlags & RATE_MCS_LDPC_MSK) ? 1 : 0;

        // MCS + NSS: radiotap packs each stream as (NSS << 4) | MCS for up to 4 users.
        uint8_t mcs = static_cast<uint8_t>(rateNFlags & RATE_MCS_CODE_MSK);
        uint8_t nss = static_cast<uint8_t>(a.spatialStreams);  // your CLI sets this

        uint8_t mcs_nss = static_cast<uint8_t>(((nss & 0x0f) << 4) | (mcs & 0x0f));

        put_le16(vht + 0, known);
        vht[2] = flags;
        vht[3] = bw;
        vht[4] = mcs_nss;  // user0
        vht[5] = 0;
        vht[6] = 0;
        vht[7] = 0;
        vht[8] = coding;
        vht[9] = 0;             // group_id
        put_le16(vht + 10, 0);  // partial_aid

        if (!rt.put_bytes_aligned(IEEE80211_RADIOTAP_VHT, vht, sizeof(vht), 2))
            return false;

    } else if (a.format == "HESU") {
        // IEEE80211_RADIOTAP_HE (bit 23): 12 bytes (6x u16 data)
        // We'll fill minimally: GI/LTF and BW if you can derive it, plus MCS/NSS if you know it.
        // Many drivers ignore HE radiotap for TX; but at least Wireshark will decode the field.
        uint16_t he[6];
        std::memset(he, 0, sizeof(he));

        // We can put BW into he[0] bits (depends on spec); without full definitions, keep it 0.
        // GI/LTF you already encode in rateNFlags via RATE_MCS_HE_GI_LTF_MSK; keep it as raw.
        // Put raw GI/LTF bits into he[0] low bits as a hint (Wireshark may not fully decode without
        // exact layout).
        he[0] =
            static_cast<uint16_t>((rateNFlags & RATE_MCS_HE_GI_LTF_MSK) >> RATE_MCS_HE_GI_LTF_POS);

        // Put MCS/NSS in he[1] as a hint (again, layout varies)
        uint8_t mcs = static_cast<uint8_t>(rateNFlags & RATE_MCS_CODE_MSK);
        uint8_t nss = static_cast<uint8_t>(a.spatialStreams);
        he[1] = static_cast<uint16_t>((nss << 8) | mcs);

        if (!rt.put_bytes_aligned(IEEE80211_RADIOTAP_HE, he, sizeof(he), 2))
            return false;

    } else {
        // Fallback: emit nothing else; still valid radiotap.
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
    if (Arguments::arguments.ltf == "2xLTF+0.8") {
        ltf = 1;
    } else if (Arguments::arguments.ltf == "2xLTF+1.6") {
        ltf = 2;
    } else if (Arguments::arguments.ltf == "4xLTF+3.2") {
        ltf = 3;
    } else if (Arguments::arguments.ltf == "4xLTF+0.8") {
        ltf = 4;
    }
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
    // For debugging clarity: broadcast destination + broadcast BSSID.
    // If you want unicast, set dst to the receiver station MAC and bssid appropriately.
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

    // open once, reuse (do not close each send)
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