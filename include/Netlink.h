/*
 * FeitCSI is the tool for extracting CSI information from supported intel NICs.
 * Copyright (C) 2023 Miroslav Hutar.
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

#ifndef NETLINK_H
#define NETLINK_H

#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <netlink/msg.h>

#define ARRAY_SIZE(ar) (sizeof(ar) / sizeof(ar[0]))

enum commandIdentifiedBy {
    CIB_NONE,
    CIB_PHY,
    CIB_NETDEV,
    CIB_WDEV,
};

struct nl80211_state {
    struct nl_sock* gnl_socket; /* Generic Netlink Socket */
    struct nl_sock* rnl_socket; /* Route Netlink Socket   */
    int nl80211_id;
};

struct Cmd {
    uint8_t id;
    commandIdentifiedBy idby;
    int nlFlags;
    signed long long device;
    int (*pre_execute_handler)(struct nl80211_state* state, struct nl_msg* msg, void* arg);
    int (*valid_handler)(struct nl_msg* msg, void* arg);
    void* pre_execute_handler_args;
    void* valid_handler_args;
};

class Netlink {
   public:
    void init();

   protected:
    struct nl80211_state nlstate;
    int nlExecCommand(Cmd& cmd);

   private:
    int nlInit(struct nl80211_state* state);

    static int error_handler(sockaddr_nl* nla, nlmsgerr* err, void* arg);
    static int finish_handler(nl_msg* msg, void* arg);
    static int ack_handler(nl_msg* msg, void* arg);
    static int nlValidHandler(nl_msg* msg, void* arg);
};

#endif