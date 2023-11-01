/*
 * local.h - Define the client's buffers and callbacks
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _LOCAL_H
#define _LOCAL_H

#include <libcork/ds.h>

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else

#include <ev.h>

#endif

#ifdef __MINGW32__
#include "winsock.h"
#endif

#include "jconf.h"

#include "common.h"

typedef struct listen_ctx {
    ev_io io;  // 连接文件监控
    char *iface;  // 绑定网卡
    int remote_num; // 远程连接数
    int timeout;  // 超时设置
    int fd;     // 连接标识符
    int mptcp;  // mptcp 是否开启
    struct sockaddr **remote_addr; // 客户端 socket 地址
} listen_ctx_t;

typedef struct server_ctx {
    ev_io io; // ev io 监听
    int connected;  // 连接标识符
    struct server *server;  // 服务端信息
} server_ctx_t;

typedef struct server {
    int fd;  // 连接符
    int stage; // 运行阶段

    cipher_ctx_t *e_ctx;    // 加密内容
    cipher_ctx_t *d_ctx;    // 解密内容
    struct server_ctx *recv_ctx;    // 服务端接收的内容
    struct server_ctx *send_ctx;    // 服务端要发送的内容
    struct listen_ctx *listener;    // 连接监听内容
    struct remote *remote;      // 远端服务器信息

    buffer_t *buf; // 缓冲区
    buffer_t *abuf; // 发送缓冲区

    ev_timer delayed_connect_watcher;  // 延时链接观察者

    struct cork_dllist_item entries;
} server_t;

// 远程连接上下文
typedef struct remote_ctx {
    ev_io io;  // 文件观察器
    ev_timer watcher; // 时间观察器
    int auth_recived;
    int connected; // 是否链接
    struct remote *remote; // 远程链接服务器
} remote_ctx_t;

// 远程链接服务器
typedef struct remote {
    int fd;  // 连接句柄
    int direct; // 是否转发
    int addr_len; // 地址长度
    uint32_t counter;
#ifdef TCP_FASTOPEN_WINSOCK
    OVERLAPPED olap;
    int connect_ex_done;
#endif

    buffer_t *buf;  // 数据报文【加密报文】

    struct remote_ctx *recv_ctx; // 远程服务器接收内容
    struct remote_ctx *send_ctx; // 远程服务器发送内容
    struct server *server; // 服务信息
    struct sockaddr_storage addr;  // 上一级服务端信息
} remote_t;

#endif // _LOCAL_H
