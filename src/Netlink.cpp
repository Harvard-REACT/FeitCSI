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

#include "Netlink.h"
#include "Logger.h"
#include "netlink/handlers.h"
#include "netlink/netlink.h"
#include "netlink/socket.h"

#include <errno.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <iostream>

void Netlink::init() {
    int err = this->nlInit(&this->nlstate);
    if (err < 0) {
        Logger::log(error) << "Unable to initialize netlink " << err << "\n";
    }
}

int Netlink::nlInit(struct nl80211_state* state) {
    int err;
    std::string errMsg;

    state->gnl_socket = nl_socket_alloc();
    if (!state->gnl_socket) {
        errMsg = "Failed to allocate generic netlink socket.\n";
        err = -ENOMEM;
        goto out_handle_destroy_generic;
    }

    if (genl_connect(state->gnl_socket)) {
        errMsg = "Failed to connect to generic netlink.\n";
        err = -ENOLINK;
        goto out_handle_destroy_generic;
    }

    nl_socket_set_buffer_size(state->gnl_socket, 8192, 8192);

    err = 1;
    setsockopt(nl_socket_get_fd(state->gnl_socket), SOL_NETLINK, NETLINK_EXT_ACK, &err,
               sizeof(err));

    state->nl80211_id = genl_ctrl_resolve(state->gnl_socket, "nl80211");
    if (state->nl80211_id < 0) {
        errMsg = "nl80211 not found.\n";
        err = -ENOENT;
        goto out_handle_destroy_generic;
    }

    state->rnl_socket = nl_socket_alloc();
    if (!state->rnl_socket) {
        throw std::ios_base::failure("Failed to allocate route socket.");
    }

    if ((err = nl_connect(state->rnl_socket, NETLINK_ROUTE)) < 0) {
        errMsg = "Failed to connect to NETLINK_ROUTE: " + std::string(nl_geterror(err)) + "\n";
        err = -ENOLINK;
        goto out_handle_destroy_route;
    }

    nl_socket_set_buffer_size(state->rnl_socket, 8192, 8192);
    err = 1;
    setsockopt(nl_socket_get_fd(state->rnl_socket), SOL_NETLINK, NETLINK_EXT_ACK, &err,
               sizeof(err));

    return 0;

out_handle_destroy_route:
    nl_socket_free(state->rnl_socket);
    state->rnl_socket = nullptr;
    // fallthrough to clean up the allocated generic socket
out_handle_destroy_generic:
    nl_socket_free(state->gnl_socket);
    state->gnl_socket = nullptr;

    if (!errMsg.empty())
        Logger::log(error) << errMsg;

    return err;
}

struct RxCtx {
    int err;
    std::string extack;
};

int Netlink::nlExecCommand(Cmd& cmd) {
    int err = 0;
    RxCtx rctx{.err = 1, .extack = {}};
    const void* valid_args[2] = {this, cmd.valid_handler_args};

    struct nl_msg* msg = nlmsg_alloc();
    if (!msg) {
        throw std::ios_base::failure("failed to allocate netlink message\n");
    }

    struct nl_cb* cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        nlmsg_free(msg);
        throw std::ios_base::failure("failed to allocate netlink callback\n");
    }
    struct nl_cb* s_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!s_cb) {
        nl_cb_put(cb);
        nlmsg_free(msg);
        throw std::ios_base::failure("failed to allocate netlink callback\n");
    }

    // Build the message
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, this->nlstate.nl80211_id, 0, cmd.nlFlags, cmd.id,
                0);

    switch (cmd.idby) {
        case CIB_PHY:
            NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, cmd.device);
            break;
        case CIB_NETDEV:
            NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, cmd.device);
            break;
        case CIB_WDEV:
            NLA_PUT_U64(msg, NL80211_ATTR_WDEV, cmd.device);
            break;
        default:
            break;
    }

    if (cmd.pre_execute_handler) {
        err = cmd.pre_execute_handler(&this->nlstate, msg, cmd.pre_execute_handler_args);
        if (err) {
            nl_cb_put(cb);
            nlmsg_free(msg);
            throw std::ios_base::failure("pre-execute handler failed");
        }
    }

    nl_socket_set_cb(this->nlstate.gnl_socket, s_cb);

    // Send
    err = nl_send_auto(this->nlstate.gnl_socket, msg);
    if (err < 0) {
        std::string text = std::string("Failed to send netlink message: ") + nl_geterror(err);
        nl_cb_put(cb);
        nlmsg_free(msg);
        throw std::ios_base::failure(text);
    }

    // Drive the recv loop with proper error collection

    // Error handler captures kernel errno + ExtAck text
    nl_cb_err(cb, NL_CB_CUSTOM, this->error_handler, &rctx);

    // FINISH/ACK drive rctx.err to 0 (use address of the member)
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, this->finish_handler, &rctx.err);
    if (!(cmd.nlFlags & NLM_F_DUMP)) {
        nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, this->ack_handler, &rctx.err);
    }

    // VALID: pass (this, user_args) as you intended — keep it alive for the whole function
    nl_cb_set(cb, NL_CB_MSG_IN, NL_CB_CUSTOM,
              cmd.valid_handler ? cmd.valid_handler : this->nlValidHandler, (void*)valid_args);

    // Receive until error (<0) or finish/ack (==0)
    while (rctx.err > 0) {
        err = nl_recvmsgs(this->nlstate.gnl_socket, cb);
        if (err < 0) {
            // libnl transport/parse error (not kernel errno)
            Logger::log(error) << "nl_recvmsgs failed (" << err << "): " << nl_geterror(err)
                               << "\n";
            break;
        }
    }

    nl_cb_put(cb);
    nlmsg_free(msg);

    // Prefer kernel errno from callbacks if present
    if (rctx.err < 0) {
        // rctx.err is a negative errno from kernel (e.g., -EBUSY, -EINVAL, ...)
        std::string why = strerror(-rctx.err);
        if (!rctx.extack.empty()) {
            Logger::log(error) << "nl80211 cmd(" << (int)cmd.id << ") failed: " << why << " ("
                               << rctx.err << ")"
                               << " — " << rctx.extack << "\n";
        } else {
            Logger::log(error) << "nl80211 cmd(" << (int)cmd.id << ") failed: " << why << " ("
                               << rctx.err << ")\n";
        }
        return rctx.err;  // propagate kernel errno
    }

    // If the libnl loop itself failed (unlikely here), bubble it up
    if (err < 0)
        return err;

    return 0;  // success

nla_put_failure:
    nl_cb_put(cb);
    nl_cb_put(s_cb);
    nlmsg_free(msg);
    throw std::ios_base::failure("building message failed\n");
}

// Robust error handler that captures ExtAck text.
int Netlink::error_handler(struct sockaddr_nl* nla, struct nlmsgerr* nlerr, void* arg) {
    RxCtx* ctx = static_cast<RxCtx*>(arg);
    if (!ctx)
        return NL_STOP;

    int kerr = nlerr->error;
    if (kerr > 0)
        kerr = -EPROTO;  // illegal per netlink(7), but be defensive
    ctx->err = kerr;

    // Try to harvest ExtAck
    struct nlmsghdr* nlh = (struct nlmsghdr*)nlerr - 1;
    int len = nlh->nlmsg_len;

    int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);
    if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
        return NL_STOP;

    if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
        ack_len += nlerr->msg.nlmsg_len - sizeof(*nlh);

    if (len <= ack_len)
        return NL_STOP;

    struct nlattr* attrs = (struct nlattr*)((unsigned char*)nlh + ack_len);
    len -= ack_len;

    struct nlattr* tb[NLMSGERR_ATTR_MAX + 1] = {};
    nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);

    std::string ext;
    if (tb[NLMSGERR_ATTR_MSG]) {
        int alen = nla_len(tb[NLMSGERR_ATTR_MSG]);
        const char* s = (const char*)nla_data(tb[NLMSGERR_ATTR_MSG]);
        ext.assign(s, strnlen(s, alen));
    }
    if (tb[NLMSGERR_ATTR_OFFS]) {
        uint32_t offs = nla_get_u32(tb[NLMSGERR_ATTR_OFFS]);
        if (!ext.empty())
            ext += "; ";
        ext += "at attribute offset " + std::to_string(offs);
    }

    ctx->extack = std::move(ext);
    return NL_STOP;
}

int Netlink::nlValidHandler(struct nl_msg* msg, void* arg) {
    return NL_OK;
}

int Netlink::finish_handler(struct nl_msg* msg, void* arg) {
    int* ret = (int*)arg;
    *ret = 0;
    return NL_SKIP;
}

int Netlink::ack_handler(struct nl_msg* msg, void* arg) {
    int* ret = (int*)arg;
    *ret = 0;
    return NL_STOP;
}

/* 1. EPERM: Operation not permitted - The requested operation is not allowed
due to insufficient permissions.
2. ESRCH: No such process - The specified process or resource could not be
found.
3. EINTR: Interrupted system call - The system call was interrupted by a signal.
4. EBADF: Bad file descriptor - The file descriptor provided is not valid.
5. EFAULT: Bad address - The provided memory address is invalid or inaccessible.
6. EINVAL: Invalid argument - One or more of the arguments provided is not
valid.
7. EIO: Input/output error - An error occurred during input or output
operations.
8. ENOMEM: Out of memory - Insufficient memory is available to complete the
requested operation.
9. EACCES: Permission denied - The requested operation is not allowed due to
permission restrictions.
10. EBUSY: Device or resource busy - The requested device or resource is
currently in use.

1. EPERM: -1
2. ESRCH: -3
3. EINTR: -4
4. EBADF: -9
5. EFAULT: -14
6. EINVAL: -22
7. EIO: -5
8. ENOMEM: -12
9. EACCES: -13
10. EBUSY: -16 */