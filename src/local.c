/*
 * local.c - Setup a socks5 proxy through remote shadowsocks server
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

#ifdef HAVE_CONFIG_H

#include "config.h"

#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>

#ifndef __MINGW32__

#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#endif
#ifdef LIB_ONLY
#include "shadowsocks.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)

#include <net/if.h>
#include <sys/ioctl.h>

#define SET_INTERFACE
#endif

#include <libcork/core.h>

#include "netutils.h"
#include "utils.h"
#include "socks5.h"
#include "acl.h"
#include "plugin.h"
#include "local.h"
#include "winsock.h"

#ifndef LIB_ONLY
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#if defined(MAC_OS_X_VERSION_10_10) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_10
#include <launch.h>
#define HAVE_LAUNCHD
#endif
#endif
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

int verbose = 0;
int reuse_port = 0;
int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;
int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;

#ifdef __ANDROID__
int vpn        = 0;
uint64_t tx    = 0;
uint64_t rx    = 0;
ev_tstamp last = 0;

char *stat_path   = NULL;
#endif

static crypto_t *crypto;

static int acl = 0;
static int mode = TCP_ONLY;
static int ipv6first = 0;
int fast_open = 0; // tcp 快速连接 cookie 验证消息
static int no_delay = 0;
static int udp_fd = 0;
static int ret_val = 0;

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
#ifndef __MINGW32__
static struct ev_signal sigchld_watcher;
static struct ev_signal sigusr1_watcher;
#else
#ifndef LIB_ONLY
static struct plugin_watcher_t {
    ev_io io;
    SOCKET fd;
    uint16_t port;
    int valid;
} plugin_watcher;
#endif
#endif

#ifdef HAVE_SETRLIMIT
#ifndef LIB_ONLY
static int nofile = 0;
#endif
#endif

static void server_recv_cb(EV_P_ ev_io *w, int revents);

static void server_send_cb(EV_P_ ev_io *w, int revents);

static void remote_recv_cb(EV_P_ ev_io *w, int revents);

static void remote_send_cb(EV_P_ ev_io *w, int revents);

static void accept_cb(EV_P_ ev_io *w, int revents);

static void signal_cb(EV_P_ ev_signal *w, int revents);

#if defined(__MINGW32__) && !defined(LIB_ONLY)
static void plugin_watcher_cb(EV_P_ ev_io *w, int revents);
#endif

static int create_and_bind(const char *addr, const char *port);

#ifdef HAVE_LAUNCHD
static int launch_or_create(const char *addr, const char *port);
#endif

static remote_t *create_remote(listen_ctx_t *listener, struct sockaddr *addr, int direct);

static void free_remote(remote_t *remote);

static void close_and_free_remote(EV_P_ remote_t *remote);

static void free_server(server_t *server);

static void close_and_free_server(EV_P_ server_t *server);

static remote_t *new_remote(int fd, int timeout);

static server_t *new_server(int fd);

static struct cork_dllist connections;

#ifndef __MINGW32__

/**
 *  在修改文件描述符标志或文件状态标志时必须谨慎，先要取得现在的标志值，然后按照希望修改它，最后设置新标志值。
 *  不能只是执行F_SETFD或F_SETFL命令，这样会关闭以前设置的标志位。
 *  根据文件描述词来操作文件的特性。
 * @param fd  文件描述符
 * @return 如果出错，所有命令都返回－1，如果成功则返回某个其他值。
 */
int
setnonblocking(int fd) {
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#endif

int
create_and_bind(const char *addr, const char *port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    result = NULL;

    // 将网络主机信息转换为 IP 地址
    /**
     * 第一个可以是指向主机名或 IPv4/IPv6 格式的地址字符串的指针。
     * 第二个参数可以是服务名称或用十进制整数表示的端口号。
     * 接下来的两个参数是指向 addrinfo 结构的指针。
     *      第一个是 hints，它指定过滤检索到的套接字结构的要求，
     *      而第二个是指针，该函数将动态分配 addrinfo 结构的链表。
     */
    s = getaddrinfo(addr, port, &hints, &result);

    if (s != 0) {
        LOGI("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    if (result == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    // TODO: 循环
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        if (reuse_port) {
            int err = set_reuseport(listen_sock);
            if (err == 0) {
                LOGI("tcp port reuse enabled");
            }
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        close(listen_sock);
        listen_sock = -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

#ifdef HAVE_LAUNCHD
int
launch_or_create(const char *addr, const char *port)
{
    int *fds;
    size_t cnt;
    int error = launch_activate_socket("Listeners", &fds, &cnt);
    if (error == 0) {
        if (cnt == 1) {
            return fds[0];
        } else {
            FATAL("please don't specify multi entry");
        }
    } else if (error == ESRCH || error == ENOENT) {
        /* ESRCH:  The calling process is not managed by launchd(8).
         * ENOENT: The socket name specified does not exist
         *          in the caller's launchd.plist(5).
         */
        if (port == NULL) {
            usage();
            exit(EXIT_FAILURE);
        }
        return create_and_bind(addr, port);
    } else {
        FATAL("launch_activate_socket() error");
    }
    return -1;
}

#endif

static void
free_connections(struct ev_loop *loop) {
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach_void(&connections, curr, next) {
        server_t *server = cork_container_of(curr, server_t, entries);
        remote_t *remote = server->remote;
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
    }
}

/**
 *  延时链接
 * @param loop libevent loop 时间类型
 * @param watcher 时间观察者
 * @param revents 事件类型
 */
static void
delayed_connect_cb(EV_P_ ev_timer *watcher, int revents) {
    server_t *server = cork_container_of(watcher, server_t,
                                         delayed_connect_watcher);

    server_recv_cb(EV_A_ &server->recv_ctx->io, revents);
}

/**
 * UDP connection  请求处理
 * @param loop 客户端连接
 * @param w 客户端连接IO观察者
 * @param udp_assc UDP 1 是
 * @param response @socks5_response socket 认证返回结果
 * @return
 */
static int
server_handshake_reply(EV_P_ ev_io *w, int udp_assc, struct socks5_response *response) {
    server_ctx_t *server_recv_ctx = (server_ctx_t *) w;
    server_t *server = server_recv_ctx->server;
    remote_t *remote = server->remote;
    if (server->stage != STAGE_HANDSHAKE)
        return 0;

    struct sockaddr_in sock_addr;
    if (udp_assc) {
        socklen_t addr_len = sizeof(sock_addr);
        // getsockname函数用于获取与某个套接字关联的本地协议地址
        if (getsockname(server->fd, (struct sockaddr *) &sock_addr, &addr_len) < 0) {
            LOGE("getsockname: %s", strerror(errno));
            // 连接目标被拒绝
            response->rep = SOCKS5_REP_CONN_REFUSED;
            send(server->fd, (char *) response, sizeof(struct socks5_response), 0);
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return -1;
        }
    } else
        memset(&sock_addr, 0, sizeof(sock_addr));

    buffer_t resp_to_send;
    buffer_t *resp_buf = &resp_to_send;
    balloc(resp_buf, SOCKET_BUF_SIZE);

    // 保存返回结果
    memcpy(resp_buf->data, response, sizeof(struct socks5_response));
    // 指针移动， 保存代理服务器地址
    memcpy(resp_buf->data + sizeof(struct socks5_response),
           &sock_addr.sin_addr, sizeof(sock_addr.sin_addr));
    // 指针移动， 保存代理服务器端口
    memcpy(resp_buf->data + sizeof(struct socks5_response) +
           sizeof(sock_addr.sin_addr),
           &sock_addr.sin_port, sizeof(sock_addr.sin_port));

    // 返回内容
    int reply_size = sizeof(struct socks5_response) +
                     sizeof(sock_addr.sin_addr) + sizeof(sock_addr.sin_port);
    // 发送字段大小
    int s = send(server->fd, resp_buf->data, reply_size, 0);

    bfree(resp_buf);

    // 判断如果发送字段小于回复字段大小，则失败
    if (s < reply_size) {
        LOGE("failed to send fake reply");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return -1;
    }
    if (udp_assc) {
        // Wait until client closes the connection
        return -1;
    }
    return 0;
}

/**
 * 和客户端握手
 * @param loop 客户端连接循环
 * @param w 客户端IO观察者
 * @param buf 接收内容
 * @return
 */
static int
server_handshake(EV_P_ ev_io *w, buffer_t *buf) {
    server_ctx_t *server_recv_ctx = (server_ctx_t *) w;
    // 代理服务器
    server_t *server = server_recv_ctx->server;
    // 远程服务器
    remote_t *remote = server->remote;

    // 代理服务器接收的内容
    struct socks5_request *request = (struct socks5_request *) buf->data;
    // socket5 请求大小
    size_t request_len = sizeof(struct socks5_request);

    if (buf->len < request_len) {
        return -1;
    }

    struct socks5_response response;
    response.ver = SVERSION;
    response.rep = SOCKS5_REP_SUCCEEDED;
    response.rsv = 0;
    response.atyp = SOCKS5_ATYP_IPV4;

    // 判断是否是UDP协议
    if (request->cmd == SOCKS5_CMD_UDP_ASSOCIATE) {
        if (verbose) {
            LOGI("udp assc request accepted");
        }
        return server_handshake_reply(EV_A_ w, 1, &response);
    } else if (request->cmd != SOCKS5_CMD_CONNECT) {
        // 判断如果不是socket 请求，则停止服务退出
        LOGE("unsupported command: %d", request->cmd);
        //  SOCKS5_REP_CMD_NOT_SUPPORTED 不支持的命令
        response.rep = SOCKS5_REP_CMD_NOT_SUPPORTED;
        char *send_buf = (char *) &response;
        send(server->fd, send_buf, 4, 0);
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return -1;
    }

    char host[MAX_HOSTNAME_LEN + 1], ip[INET6_ADDRSTRLEN], port[16];

    // 代理服务器接收到的内容
    buffer_t *abuf = server->abuf;
    abuf->idx = 0;
    abuf->len = 0;

    // 地址类型 1 个字节
    abuf->data[abuf->len++] = request->atyp;
    int atyp = request->atyp;

    // get remote addr and port
    if (atyp == SOCKS5_ATYP_IPV4) {
        // 地址类型 : IP4
        size_t in_addr_len = sizeof(struct in_addr);
        // 长度构成：请求体大小+目标地址+端口
        if (buf->len < request_len + in_addr_len + 2) {
            return -1;
        }
        // 拷贝 接收的内容到发送缓冲区abuf
        memcpy(abuf->data + abuf->len, buf->data + request_len, in_addr_len + 2);
        abuf->len += in_addr_len + 2;

        if (acl || verbose) {
            // xxxx 可能转16进制
            uint16_t p = load16_be(buf->data + request_len + in_addr_len);
            // 将IP地址在“点分十进制”和“二进制整数”之间转换。
            // 获得 ip
            if (!inet_ntop(AF_INET, (const void *) (buf->data + request_len),
                           ip, INET_ADDRSTRLEN)) {
                LOGI("inet_ntop(AF_INET): %s", strerror(errno));
                ip[0] = '\0';
            }
            sprintf(port, "%d", p);
        }
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        // 地址类型 : domain
        uint8_t name_len = *(uint8_t *) (buf->data + request_len);
        if (buf->len < request_len + 1 + name_len + 2) {
            return -1;
        }
        abuf->data[abuf->len++] = name_len;
        // 拷贝请求域名
        memcpy(abuf->data + abuf->len, buf->data + request_len + 1, name_len + 2);
        abuf->len += name_len + 2;

        if (acl || verbose) {
            uint16_t p = load16_be(buf->data + request_len + 1 + name_len);
            // 获取域名
            memcpy(host, buf->data + request_len + 1, name_len);
            host[name_len] = '\0';
            sprintf(port, "%d", p);
        }
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        // 地址类型 : IPv6
        size_t in6_addr_len = sizeof(struct in6_addr);
        if (buf->len < request_len + in6_addr_len + 2) {
            return -1;
        }
        memcpy(abuf->data + abuf->len, buf->data + request_len, in6_addr_len + 2);
        abuf->len += in6_addr_len + 2;

        if (acl || verbose) {
            uint16_t p = load16_be(buf->data + request_len + in6_addr_len);
            if (!inet_ntop(AF_INET6, (const void *) (buf->data + request_len),
                           ip, INET6_ADDRSTRLEN)) {
                LOGI("inet_ntop(AF_INET6): %s", strerror(errno));
                ip[0] = '\0';
            }
            sprintf(port, "%d", p);
        }
    } else {
        // 不支持的网络地址类型
        LOGE("unsupported addrtype: %d", request->atyp);
        // SOCKS5_REP_ADDRTYPE_NOT_SUPPORTED  不支持的目标服务器地址类型
        response.rep = SOCKS5_REP_ADDRTYPE_NOT_SUPPORTED;
        char *send_buf = (char *) &response;
        send(server->fd, send_buf, 4, 0);
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return -1;
    }

    if (server_handshake_reply(EV_A_ w, 0, &response) < 0)
        return -1;

    // 修改代理服务器阶段， 客户端和服务器数据报文
    server->stage = STAGE_STREAM;

    buf->len -= (3 + abuf->len);
    if (buf->len > 0) {
        memmove(buf->data, buf->data + 3 + abuf->len, buf->len);
    }

    if (verbose) {
        if (atyp == SOCKS5_ATYP_DOMAIN)
            LOGI("connect to %s:%s", host, port);
        else if (atyp == SOCKS5_ATYP_IPV4)
            LOGI("connect to %s:%s", ip, port);
        else if (atyp == SOCKS5_ATYP_IPV6)
            LOGI("connect to [%s]:%s", ip, port);
    }

    if (acl
#ifdef __ANDROID__
        && !(vpn && strcmp(port, "53") == 0)
#endif
            ) {
        int bypass = 0;
        int resolved = 0;
        struct sockaddr_storage storage;
        memset(&storage, 0, sizeof(struct sockaddr_storage));
        int err;

        int host_match = 0;
        if (atyp == SOCKS5_ATYP_DOMAIN)
            // 匹配访问的域名是否在acl 文件中
            host_match = acl_match_host(host);

        if (host_match > 0)
            bypass = 1;                             // bypass hostnames in black list
        else if (host_match < 0)
            bypass = 0;                             // proxy hostnames in white list
        else {

            // 如果为域名
            if (atyp == SOCKS5_ATYP_DOMAIN
#ifdef __ANDROID__
                && !vpn
#endif
                    ) {
                // resolve domain so we can bypass domain with geoip
                // 转换 域名为 IP 地址
                if (get_sockaddr(host, port, &storage, 0, ipv6first))
                    goto not_bypass;
                resolved = 1;
                switch (((struct sockaddr *) &storage)->sa_family) {
                    case AF_INET: {
                        struct sockaddr_in *addr_in = (struct sockaddr_in *) &storage;
                        if (!inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN))
                            goto not_bypass;
                        break;
                    }
                    case AF_INET6: {
                        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) &storage;
                        if (!inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip, INET6_ADDRSTRLEN))
                            goto not_bypass;
                        break;
                    }
                    default:
                        goto not_bypass;
                }
            }

            // IP 匹配模式
            int ip_match = (resolved || atyp == SOCKS5_ATYP_IPV4
                            || atyp == SOCKS5_ATYP_IPV6) ? acl_match_host(ip) : 0;

            // 默认是黑名单
            switch (get_acl_mode()) {
                case BLACK_LIST:
                    if (ip_match > 0)
                        bypass = 1;                                               // bypass IPs in black list
                    break;
                case WHITE_LIST:
                    bypass = 1;
                    if (ip_match < 0)
                        bypass = 0;                                               // proxy IPs in white list
                    break;
            }
        }

        // 通过则机械， 连接远程服务端
        if (bypass) {
            if (verbose) {
                if (atyp == SOCKS5_ATYP_DOMAIN)
                    LOGI("bypass %s:%s", host, port);
                else if (atyp == 1)
                    LOGI("bypass %s:%s", ip, port);
                else if (atyp == 4)
                    LOGI("bypass [%s]:%s", ip, port);
            }
            if (atyp == SOCKS5_ATYP_DOMAIN && !resolved)
#ifdef __ANDROID__
                if (vpn)
                    goto not_bypass;
                else
#endif
                err = get_sockaddr(host, port, &storage, 0, ipv6first);
            else
                err = get_sockaddr(ip, port, &storage, 0, ipv6first);

            // 获取远程服务器的IP和端口
            if (err != -1) {
                // 创建远程链接， 转发代理服务器请求
                remote = create_remote(server->listener, (struct sockaddr *) &storage, 1);
            }
        }
    }

    not_bypass:
    // Not bypass
    if (remote == NULL) {
        remote = create_remote(server->listener, NULL, 0);
    }

    if (remote == NULL) {
        LOGE("invalid remote addr");
        close_and_free_server(EV_A_ server);
        return -1;
    }

    if (!remote->direct) {
        int err = crypto->encrypt(abuf, server->e_ctx, SOCKET_BUF_SIZE);
        if (err) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return -1;
        }
    }

    if (buf->len > 0) {
        memcpy(remote->buf->data, buf->data, buf->len);
        remote->buf->len = buf->len;
    }

    server->remote = remote;
    remote->server = server;

    if (buf->len > 0) {
        return 0;
    } else {
        ev_timer_start(EV_A_ &server->delayed_connect_watcher);
    }

    return -1;
}

/**
 * 服务器端上下文内容
 * @param loop 循环对象
 * @param w 观察器
 * @param buf server recv 缓冲区内容
 */
static void
server_stream(EV_P_ ev_io *w, buffer_t *buf) {
    server_ctx_t *server_recv_ctx = (server_ctx_t *) w;
    server_t *server = server_recv_ctx->server;
    remote_t *remote = server->remote;

    if (remote == NULL) {
        LOGE("invalid remote");
        close_and_free_server(EV_A_ server);
        return;
    }

    // insert shadowsocks header
    // 判断是远程服务器转发
    if (!remote->direct) {
#ifdef __ANDROID__
        tx += remote->buf->len;
#endif
        int err = crypto->encrypt(remote->buf, server->e_ctx, SOCKET_BUF_SIZE);

        if (err) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }

        if (server->abuf) {
            // 合并内容
            bprepend(remote->buf, server->abuf, SOCKET_BUF_SIZE);
            bfree(server->abuf);
            ss_free(server->abuf);
            server->abuf = NULL;
        }
    }

    if (!remote->send_ctx->connected) {
#ifdef __ANDROID__
        if (vpn) {
            int not_protect = 0;
            if (remote->addr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&remote->addr;
                if (s->sin_addr.s_addr == inet_addr("127.0.0.1"))
                    not_protect = 1;
            }
            if (!not_protect) {
                if (protect_socket(remote->fd) == -1) {
                    ERROR("protect_socket");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }
        }
#endif

        remote->buf->idx = 0;

        //  判断是否开启快速连接，并且是转发
        if (!fast_open || remote->direct) {
            // connecting, wait until connected
            // TODO: 连接远程服务器
            int r = connect(remote->fd, (struct sockaddr *) &(remote->addr), remote->addr_len);

            if (r == -1 && errno != CONNECT_IN_PROGRESS) {
                ERROR("connect");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            // wait on remote connected event
            // 结束本机服务端接收监听
            ev_io_stop(EV_A_ &server_recv_ctx->io);
            // 启动远程服务器文件的发送，和延时监听
            ev_io_start(EV_A_ &remote->send_ctx->io);
            ev_timer_start(EV_A_ &remote->send_ctx->watcher);
        } else {
#if defined(MSG_FASTOPEN) && !defined(TCP_FASTOPEN_CONNECT)
            int s = -1;
            s = sendto(remote->fd, remote->buf->data, remote->buf->len, MSG_FASTOPEN,
                       (struct sockaddr *)&(remote->addr), remote->addr_len);
#elif defined(TCP_FASTOPEN_WINSOCK)
            DWORD s   = -1;
            DWORD err = 0;
            do {
                int optval = 1;
                // Set fast open option
                if (setsockopt(remote->fd, IPPROTO_TCP, TCP_FASTOPEN,
                               &optval, sizeof(optval)) != 0) {
                    ERROR("setsockopt");
                    break;
                }
                // Load ConnectEx function
                LPFN_CONNECTEX ConnectEx = winsock_getconnectex();
                if (ConnectEx == NULL) {
                    LOGE("Cannot load ConnectEx() function");
                    err = WSAENOPROTOOPT;
                    break;
                }
                // ConnectEx requires a bound socket
                if (winsock_dummybind(remote->fd,
                                      (struct sockaddr *)&(remote->addr)) != 0) {
                    ERROR("bind");
                    break;
                }
                // Call ConnectEx to send data
                memset(&remote->olap, 0, sizeof(remote->olap));
                remote->connect_ex_done = 0;
                if (ConnectEx(remote->fd, (const struct sockaddr *)&(remote->addr),
                              remote->addr_len, remote->buf->data, remote->buf->len,
                              &s, &remote->olap)) {
                    remote->connect_ex_done = 1;
                    break;
                }
                // XXX: ConnectEx pending, check later in remote_send
                if (WSAGetLastError() == ERROR_IO_PENDING) {
                    err = CONNECT_IN_PROGRESS;
                    break;
                }
                ERROR("ConnectEx");
            } while (0);
            // Set error number
            if (err) {
                SetLastError(err);
            }
#else
            int s = -1;
#if defined(CONNECT_DATA_IDEMPOTENT)
            ((struct sockaddr_in *)&(remote->addr))->sin_len = sizeof(struct sockaddr_in);
            sa_endpoints_t endpoints;
            memset((char *)&endpoints, 0, sizeof(endpoints));
            endpoints.sae_dstaddr    = (struct sockaddr *)&(remote->addr);
            endpoints.sae_dstaddrlen = remote->addr_len;

            s = connectx(remote->fd, &endpoints, SAE_ASSOCID_ANY,
                         CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
                         NULL, 0, NULL, NULL);
#elif defined(TCP_FASTOPEN_CONNECT)
            // 开启TCP 快速连接 ， 再握手的时候存储cookies , 下次链接直接携带存储的cookies+data，
            // 通过 cookie 是否有效直接接收数据，否则返回新的cookie
            int optval = 1;
            if (setsockopt(remote->fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                           (void *) &optval, sizeof(optval)) < 0)
                FATAL("failed to set TCP_FASTOPEN_CONNECT");

            // todo: 连接远端服务器
            s = connect(remote->fd, (struct sockaddr *) &(remote->addr), remote->addr_len);
#else
            FATAL("fast open is not enabled in this build");
#endif
            // TODO: 连接成功发送内容 s 为发送的字节数
            if (s == 0)
                s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
#endif
            if (s == -1) {
                // 连接中状态
                if (errno == CONNECT_IN_PROGRESS) {
                    // in progress, wait until connected
                    remote->buf->idx = 0;
                    ev_io_stop(EV_A_ &server_recv_ctx->io);
                    ev_io_start(EV_A_ &remote->send_ctx->io);
                    return;
                } else {
                    /**
                     * EOPNOTSUPP  套接字类型不是 socket_stream
                     * EPROTONOSUPPORT  协议不支持
                     * ENOPROTOOPT  协议不可用
                     */
                    if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                        errno == ENOPROTOOPT) {
                        LOGE("fast open is not supported on this platform");
                        // just turn it off
                        fast_open = 0;
                    } else {
                        ERROR("fast_open_connect");
                    }
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            } else {
                // 远程服务器的长度减去发送的长度 ，指针后移动 S 位
                remote->buf->len -= s;
                remote->buf->idx = s;

                // 停止本机服务端接收的监听 ，
                ev_io_stop(EV_A_ &server_recv_ctx->io);
                // 开始监听连接远程服务器发送行为和 返回的时间观察
                ev_io_start(EV_A_ &remote->send_ctx->io);
                ev_timer_start(EV_A_ &remote->send_ctx->watcher);
                return;
            }
        }
    } else {
        int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
        if (s == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data, wait for send
                remote->buf->idx = 0;
                ev_io_stop(EV_A_ &server_recv_ctx->io);
                ev_io_start(EV_A_ &remote->send_ctx->io);
                return;
            } else {
                ERROR("server_recv_cb_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        } else if (s < (int) (remote->buf->len)) {
            remote->buf->len -= s;
            remote->buf->idx = s;
            ev_io_stop(EV_A_ &server_recv_ctx->io);
            ev_io_start(EV_A_ &remote->send_ctx->io);
            return;
        } else {
            remote->buf->idx = 0;
            remote->buf->len = 0;
        }
    }
}

/**
 * 处理客户端接收内容
 * @param loop 循环对象
 * @param w 客户端连接标识符
 * @param revents  事件 Read
 */
static void
server_recv_cb(EV_P_ ev_io *w, int revents) {
    // 服务端接收客户端链接上下文对象
    server_ctx_t *server_recv_ctx = (server_ctx_t *) w;
    // 服务端信息
    server_t *server = server_recv_ctx->server;
    // 连接请求的远程服务端
    remote_t *remote = server->remote;
    buffer_t *buf; // buffer 接收内容
    ssize_t r;  // 接收的字符串长度

    //todo:: why 停止延迟连接观察
    ev_timer_stop(EV_A_ &server->delayed_connect_watcher);

    if (remote == NULL) {
        buf = server->buf;
    } else {
        // 接收内容赋值给远程服务器对象
        buf = remote->buf;
    }

    // 判断是否为时间观察器 【 EV_TIMER 超时】
    if (revents != EV_TIMER) {
        // 接收内容的长度
        // todo::  详细计算规则
        r = recv(server->fd, buf->data + buf->len, SOCKET_BUF_SIZE - buf->len, 0);

        // 没有接收到内容， 关闭本地服务和远程服务连接
        if (r == 0) {
            // connection closed
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        } else if (r == -1) {
            // 程序没有数据可读，稍后重试
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data
                // continue to wait for recv
                return;
            } else {
                // 释放资源
                if (verbose)
                    ERROR("server_recv_cb_recv");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
        // 内容长度
        buf->len += r;
    }

    while (1) {
        // local socks5 server
        if (server->stage == STAGE_STREAM) {
            server_stream(EV_A_ w, buf);

            // all processed
            return;
        } else if (server->stage == STAGE_INIT) {
            // 初始化阶段
            if (verbose) {
                struct sockaddr_in peer_addr;
                socklen_t peer_addr_len = sizeof peer_addr;
                // getpeername函数用于获取与某个套接字关联的外地协议地址
                // getsockname函数用于获取与某个套接字关联的本地协议地址
                if (getpeername(server->fd, (struct sockaddr *) &peer_addr, &peer_addr_len) == 0) {
                    LOGI("connection from %s:%hu", inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));
                }
            }
            if (buf->len < 1)
                return;
            // VERSION SOCKS协议版本，目前固定0x05
            if (buf->data[0] != SVERSION) {
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
            // +----+----------+----------+
            // |VER | NMETHODS | METHODS  |
            // +----+----------+----------+
            // | 1  |    1     | 1 to 255 |
            // +----+----------+----------+
            // VER: 协议版本，socks5为0x05
            // NMETHODS: 支持认证的方法数量
            // METHODS: 对应NMETHODS，NMETHODS的值为多少，METHODS就有多少个字节。RFC预定义了一些值的含义，内容如下:
            // X’00’ NO AUTHENTICATION REQUIRED
            // X’02’ USERNAME/PASSWOR

            // todo 不懂，
            if (buf->len < sizeof(struct method_select_request)) {
                return;
            }
            struct method_select_request *method = (struct method_select_request *) buf->data;
            // 方法长度 = 支持的方法数+结构体大小
            int method_len = method->nmethods + sizeof(struct method_select_request);
            if (buf->len < method_len) {
                return;
            }

            // 认证返回结果
            struct method_select_response response;
            response.ver = SVERSION; // 0x05 socket 固定协议版本
            response.method = METHOD_UNACCEPTABLE;  // 无支持的认证方法
            for (int i = 0; i < method->nmethods; i++)
                // 无需认证
                if (method->methods[i] == METHOD_NOAUTH) {
                    response.method = METHOD_NOAUTH;
                    break;
                }
            // TODO 返回客户端认证方式：无需认证
            char *send_buf = (char *) &response;
            send(server->fd, send_buf, sizeof(response), 0);
            if (response.method == METHOD_UNACCEPTABLE) {
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            // 修改服务阶段为：和客户端握手
            server->stage = STAGE_HANDSHAKE;

            if (method_len < (int) (buf->len)) {
                // 覆盖复制， 设置内容为内容    缓冲区 ， 缓冲区+支持的方法长度， 缓冲区内容长度-方法长度
                memmove(buf->data, buf->data + method_len, buf->len - method_len);
                buf->len -= method_len;
                continue;
            }

            buf->len = 0;
            return;
        } else if (server->stage == STAGE_HANDSHAKE) {
            // 和客户度握手
            int ret = server_handshake(EV_A_ w, buf);
            if (ret)
                return;
        }
    }
}

static void
server_send_cb(EV_P_ ev_io *w, int revents) {
    server_ctx_t *server_send_ctx = (server_ctx_t *) w;
    server_t *server = server_send_ctx->server;
    remote_t *remote = server->remote;
    if (server->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_cb_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < (ssize_t) (server->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ &server_send_ctx->io);
            ev_io_start(EV_A_ &remote->recv_ctx->io);
            return;
        }
    }
}

#ifdef __ANDROID__
void
stat_update_cb()
{
    ev_tstamp now = ev_time();
    if (now - last > 0.5) {
        send_traffic_stat(tx, rx);
        last = now;
    }
}

#endif

static void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents) {
    remote_ctx_t *remote_ctx
            = cork_container_of(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;

    if (verbose) {
        LOGI("TCP connection timeout");
    }

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void
remote_recv_cb(EV_P_ ev_io *w, int revents) {
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *) w;
    remote_t *remote = remote_recv_ctx->remote;
    server_t *server = remote->server;

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote_recv_cb_recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf->len = r;

    if (!remote->direct) {
#ifdef __ANDROID__
        rx += server->buf->len;
        stat_update_cb();
#endif
        int err = crypto->decrypt(server->buf, server->d_ctx, SOCKET_BUF_SIZE);
        if (err == CRYPTO_ERROR) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        } else if (err == CRYPTO_NEED_MORE) {
            return; // Wait for more
        }
    }

    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ &remote_recv_ctx->io);
            ev_io_start(EV_A_ &server->send_ctx->io);
        } else {
            ERROR("remote_recv_cb_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < (int) (server->buf->len)) {
        server->buf->len -= s;
        server->buf->idx = s;
        ev_io_stop(EV_A_ &remote_recv_ctx->io);
        ev_io_start(EV_A_ &server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected && !no_delay) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

static void
remote_send_cb(EV_P_ ev_io *w, int revents) {
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *) w;
    remote_t *remote = remote_send_ctx->remote;
    server_t *server = remote->server;

    if (!remote_send_ctx->connected) {
#ifdef TCP_FASTOPEN_WINSOCK
        if (fast_open) {
            // Check if ConnectEx is done
            if (!remote->connect_ex_done) {
                DWORD numBytes;
                DWORD flags;
                // Non-blocking way to fetch ConnectEx result
                if (WSAGetOverlappedResult(remote->fd, &remote->olap,
                                           &numBytes, FALSE, &flags)) {
                    remote->buf->len       -= numBytes;
                    remote->buf->idx        = numBytes;
                    remote->connect_ex_done = 1;
                } else if (WSAGetLastError() == WSA_IO_INCOMPLETE) {
                    // XXX: ConnectEx still not connected, wait for next time
                    return;
                } else {
                    ERROR("WSAGetOverlappedResult");
                    // not connected
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }

            // Make getpeername work
            if (setsockopt(remote->fd, SOL_SOCKET,
                           SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
                ERROR("setsockopt");
            }
        }
#endif
        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r = getpeername(remote->fd, (struct sockaddr *) &addr, &len);
        if (r == 0) {
            remote_send_ctx->connected = 1;
            ev_timer_stop(EV_A_ &remote_send_ctx->watcher);
            ev_io_start(EV_A_ &remote->recv_ctx->io);

            // no need to send any data
            if (remote->buf->len == 0) {
                ev_io_stop(EV_A_ &remote_send_ctx->io);
                ev_io_start(EV_A_ &server->recv_ctx->io);
                return;
            }
        } else {
            // not connected
            ERROR("getpeername");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_cb_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < (ssize_t) (remote->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ &remote_send_ctx->io);
            ev_io_start(EV_A_ &server->recv_ctx->io);
        }
    }
}

static remote_t *
new_remote(int fd, int timeout) {
    remote_t *remote;
    remote = ss_malloc(sizeof(remote_t));

    memset(remote, 0, sizeof(remote_t));

    remote->buf = ss_malloc(sizeof(buffer_t));
    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    balloc(remote->buf, SOCKET_BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->recv_ctx->connected = 0;
    remote->send_ctx->connected = 0;
    remote->fd = fd;
    remote->recv_ctx->remote = remote;
    remote->send_ctx->remote = remote;

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT, timeout), 0);

    return remote;
}

/**
 * 释放远程服务器资源
 * @param remote  远程服务器
 */
static void
free_remote(remote_t *remote) {
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

/**
 * 关闭和释放服务器资源
 * @param loop 循环器
 * @param remote 远程服务器
 */
static void
close_and_free_remote(EV_P_ remote_t *remote) {
    if (remote != NULL) {
        // 停止观察延时， 停止观察发送和接收的IO操作
        ev_timer_stop(EV_A_ &remote->send_ctx->watcher);
        ev_io_stop(EV_A_ &remote->send_ctx->io);
        ev_io_stop(EV_A_ &remote->recv_ctx->io);
        // 关闭连接
        close(remote->fd);
        // 释放远程服务器资源
        free_remote(remote);
    }
}

/**
 * 创建新的服务，处理请求， 连接远程服务器
 * @param fd  连接标识符
 * @return server_t
 */
static server_t *
new_server(int fd) {
    server_t *server;
    server = ss_malloc(sizeof(server_t));

    memset(server, 0, sizeof(server_t));

    server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(server_ctx_t));
    server->buf = ss_malloc(sizeof(buffer_t));
    server->abuf = ss_malloc(sizeof(buffer_t));

    balloc(server->buf, SOCKET_BUF_SIZE);
    balloc(server->abuf, SOCKET_BUF_SIZE);

    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));

    server->stage = STAGE_INIT;
    server->recv_ctx->connected = 0;
    server->send_ctx->connected = 0;
    server->fd = fd;
    server->recv_ctx->server = server;
    server->send_ctx->server = server;

    server->e_ctx = ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx = ss_malloc(sizeof(cipher_ctx_t));
    crypto->ctx_init(crypto->cipher, server->e_ctx, 1);
    crypto->ctx_init(crypto->cipher, server->d_ctx, 0);

    // todo:: 监听服务端接收， 处理接收的内容
    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    // todo:: 监听服务端发送数据， 写入  处理返回的内容
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

    ev_timer_init(&server->delayed_connect_watcher,
                  delayed_connect_cb, 0.05, 0);

            cork_dllist_add(&connections, &server->entries);

    return server;
}

static void
free_server(server_t *server) {
    cork_dllist_remove(&server->entries);

    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->e_ctx != NULL) {
        crypto->ctx_release(server->e_ctx);
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        crypto->ctx_release(server->d_ctx);
        ss_free(server->d_ctx);
    }
    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }
    if (server->abuf != NULL) {
        bfree(server->abuf);
        ss_free(server->abuf);
    }
    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void
close_and_free_server(EV_P_ server_t *server) {
    if (server != NULL) {
        ev_io_stop(EV_A_ &server->send_ctx->io);
        ev_io_stop(EV_A_ &server->recv_ctx->io);
        ev_timer_stop(EV_A_ &server->delayed_connect_watcher);
        close(server->fd);
        free_server(server);
    }
}

/**
 * 创建远程代理服务器本地服务端
 * @param listener 客户端连接
 * @param addr 目标地址
 * @param direct 是否转发 1
 * @return
 */
static remote_t *
create_remote(listen_ctx_t *listener,
              struct sockaddr *addr,
              int direct) {
    struct sockaddr *remote_addr;

    int index = rand() % listener->remote_num;
    if (addr == NULL) {
        remote_addr = listener->remote_addr[index];
    } else {
        remote_addr = addr;
    }

    int protocol = IPPROTO_TCP;
    if (listener->mptcp < 0) {
        protocol = IPPROTO_MPTCP; // Enable upstream MPTCP
    }
    int remotefd = socket(remote_addr->sa_family, SOCK_STREAM, protocol);
    if (remotefd == -1) {
        ERROR("socket");
        return NULL;
    }

    int opt = 1;
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // Enable out-of-tree MPTCP
    if (listener->mptcp > 1) {
        int err = setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
        if (err == -1) {
            ERROR("failed to enable out-of-tree multipath TCP");
        }
    } else if (listener->mptcp == 1) {
        int i = 0;
        while ((listener->mptcp = mptcp_enabled_values[i]) > 0) {
            int err = setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
            if (err != -1) {
                break;
            }
            i++;
        }
        if (listener->mptcp == 0) {
            ERROR("failed to enable out-of-tree multipath TCP");
        }
    }

    if (tcp_outgoing_sndbuf > 0) {
        setsockopt(remotefd, SOL_SOCKET, SO_SNDBUF, &tcp_outgoing_sndbuf, sizeof(int));
    }

    if (tcp_outgoing_rcvbuf > 0) {
        setsockopt(remotefd, SOL_SOCKET, SO_RCVBUF, &tcp_outgoing_rcvbuf, sizeof(int));
    }

    // Setup
    setnonblocking(remotefd);
#ifdef SET_INTERFACE
    if (listener->iface) {
        if (setinterface(remotefd, listener->iface) == -1)
            ERROR("setinterface");
    }
#endif

    remote_t *remote = new_remote(remotefd, direct ? MAX_CONNECT_TIMEOUT : listener->timeout);
    remote->addr_len = get_sockaddr_len(remote_addr);
    memcpy(&(remote->addr), remote_addr, remote->addr_len);
    remote->direct = direct;

    if (verbose) {
        struct sockaddr_in *sockaddr = (struct sockaddr_in *) &remote->addr;
        LOGI("remote: %s:%hu", inet_ntoa(sockaddr->sin_addr), ntohs(sockaddr->sin_port));
    }

    return remote;
}

/**
 *  信号型号
 * @param loop 监听时间
 * @param w
 * @param revents 中断信号
 */
static void
signal_cb(EV_P_ ev_signal *w, int revents) {
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
#ifndef __MINGW32__
            case SIGCHLD: // 子进程结束时, 父进程会收到这个信号
                if (!is_plugin_running()) {
                    LOGE("plugin service exit unexpectedly");
                    ret_val = -1;
                } else
                    return;
            case SIGUSR1: // 用户使用
#endif
            case SIGINT: // ctrl-c
            case SIGTERM: // kill signal
                // 主动停止事件观察者
                ev_signal_stop(EV_DEFAULT, &sigint_watcher);
                ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
#ifndef __MINGW32__
                ev_signal_stop(EV_DEFAULT, &sigchld_watcher);
                ev_signal_stop(EV_DEFAULT, &sigusr1_watcher);
#else
#ifndef LIB_ONLY
                ev_io_stop(EV_DEFAULT, &plugin_watcher.io);
#endif
#endif
                // 会让ev_run停止所有事件.
                ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

#if defined(__MINGW32__) && !defined(LIB_ONLY)
static void
plugin_watcher_cb(EV_P_ ev_io *w, int revents)
{
    char buf[1];
    SOCKET fd = accept(plugin_watcher.fd, NULL, NULL);
    if (fd == INVALID_SOCKET) {
        return;
    }
    recv(fd, buf, 1, 0);
    closesocket(fd);
    LOGE("plugin service exit unexpectedly");
    ret_val = -1;
    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
    ev_io_stop(EV_DEFAULT, &plugin_watcher.io);
    ev_unloop(EV_A_ EVUNLOOP_ALL);
}

#endif

/**
 * 处理请求
 * @param loop  事件循环对象
 * @param w 客户端连接
 * @param revents 读数据 READ
 */
void
accept_cb(EV_P_ ev_io *w, int revents) {
    listen_ctx_t *listener = (listen_ctx_t *) w;
    // 接收请求
    int serverfd = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }
    setnonblocking(serverfd);
    // 关闭数据包缓存
    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // 设置 socket 发送缓冲区大小
    if (tcp_incoming_sndbuf > 0) {
        setsockopt(serverfd, SOL_SOCKET, SO_SNDBUF, &tcp_incoming_sndbuf, sizeof(int));
    }

    // 设置 socket 接收缓冲区大小
    if (tcp_incoming_rcvbuf > 0) {
        setsockopt(serverfd, SOL_SOCKET, SO_RCVBUF, &tcp_incoming_rcvbuf, sizeof(int));
    }

    // 根据客户端连接，新建服务端
    server_t *server = new_server(serverfd);
    server->listener = listener;

    ev_io_start(EV_A_ &server->recv_ctx->io);
}

#ifndef LIB_ONLY

int
main(int argc, char **argv) {
    int i, c;
    int pid_flags = 0;
    int mtu = 0;
    int mptcp = 0;
    char *user = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *password = NULL;
    char *key = NULL;
    char *timeout = NULL;
    char *method = NULL;
    char *pid_path = NULL;
    char *conf_path = NULL;
    char *iface = NULL;

    char *plugin = NULL;
    char *plugin_opts = NULL;
    char *plugin_host = NULL;
    char *plugin_port = NULL;
    char tmp_port[8];

    int remote_num = 0;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;

    memset(remote_addr, 0, sizeof(ss_addr_t) * MAX_REMOTE_NUM);
    srand(time(NULL));

    static struct option long_options[] = {
            {"reuse-port",          no_argument,       NULL, GETOPT_VAL_REUSE_PORT},
            {"tcp-incoming-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_SNDBUF},
            {"tcp-incoming-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_RCVBUF},
            {"tcp-outgoing-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_SNDBUF},
            {"tcp-outgoing-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_RCVBUF},
            {"fast-open",           no_argument,       NULL, GETOPT_VAL_FAST_OPEN},
            {"no-delay",            no_argument,       NULL, GETOPT_VAL_NODELAY},
            {"acl",                 required_argument, NULL, GETOPT_VAL_ACL},
            {"mtu",                 required_argument, NULL, GETOPT_VAL_MTU},
            {"mptcp",               no_argument,       NULL, GETOPT_VAL_MPTCP},
            {"plugin",              required_argument, NULL, GETOPT_VAL_PLUGIN},
            {"plugin-opts",         required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS},
            {"password",            required_argument, NULL, GETOPT_VAL_PASSWORD},
            {"key",                 required_argument, NULL, GETOPT_VAL_KEY},
            {"help",                no_argument,       NULL, GETOPT_VAL_HELP},
            {NULL, 0,                                  NULL, 0}
    };

    opterr = 0;

    USE_TTY();

#ifdef __ANDROID__
    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:i:c:b:a:n:S:huUvV6A",
                            long_options, NULL)) != -1) {
#else
    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:i:c:b:a:n:huUv6A",
                            long_options, NULL)) != -1) {
#endif
        switch (c) {
            case GETOPT_VAL_FAST_OPEN:
                fast_open = 1;
                break;
            case GETOPT_VAL_ACL:
                LOGI("initializing acl...");
                acl = !init_acl(optarg);
                break;
            case GETOPT_VAL_MTU:
                mtu = atoi(optarg);
                LOGI("set MTU to %d", mtu);
                break;
            case GETOPT_VAL_MPTCP:
                mptcp = get_mptcp(1);
                if (mptcp)
                    LOGI("enable multipath TCP (%s)", mptcp > 0 ? "out-of-tree" : "upstream");
                break;
            case GETOPT_VAL_NODELAY:
                no_delay = 1;
                LOGI("enable TCP no-delay");
                break;
            case GETOPT_VAL_PLUGIN:
                plugin = optarg;
                break;
            case GETOPT_VAL_PLUGIN_OPTS:
                plugin_opts = optarg;
                break;
            case GETOPT_VAL_KEY:
                key = optarg;
                break;
            case GETOPT_VAL_REUSE_PORT:
                reuse_port = 1;
                break;
            case GETOPT_VAL_TCP_INCOMING_SNDBUF:
                tcp_incoming_sndbuf = atoi(optarg);
                break;
            case GETOPT_VAL_TCP_INCOMING_RCVBUF:
                tcp_incoming_rcvbuf = atoi(optarg);
                break;
            case GETOPT_VAL_TCP_OUTGOING_SNDBUF:
                tcp_outgoing_sndbuf = atoi(optarg);
                break;
            case GETOPT_VAL_TCP_OUTGOING_RCVBUF:
                tcp_outgoing_rcvbuf = atoi(optarg);
                break;
            case 's':
                if (remote_num < MAX_REMOTE_NUM) {
                    parse_addr(optarg, &remote_addr[remote_num++]);
                }
                break;
            case 'p':
                remote_port = optarg;
                break;
            case 'l':
                local_port = optarg;
                break;
            case GETOPT_VAL_PASSWORD:
            case 'k':
                password = optarg;
                break;
            case 'f':
                pid_flags = 1;
                pid_path = optarg;
                break;
            case 't':
                timeout = optarg;
                break;
            case 'm':
                method = optarg;
                break;
            case 'c':
                conf_path = optarg;
                break;
            case 'i':
                iface = optarg;
                break;
            case 'b':
                local_addr = optarg;
                break;
            case 'a':
                user = optarg;
                break;
#ifdef HAVE_SETRLIMIT
            case 'n':
                nofile = atoi(optarg);
                break;
#endif
            case 'u':
                mode = TCP_AND_UDP;
                break;
            case 'U':
                mode = UDP_ONLY;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
            case GETOPT_VAL_HELP:
                usage();
                exit(EXIT_SUCCESS);
            case '6':
                ipv6first = 1;
                break;
#ifdef __ANDROID__
                case 'S':
                    stat_path = optarg;
                    break;
                case 'V':
                    vpn = 1;
                    break;
#endif
            case 'A':
                FATAL("One time auth has been deprecated. Try AEAD ciphers instead.");
                break;
            case '?':
                // The option character is not recognized.
                LOGE("Unrecognized option: %s", optarg);
                opterr = 1;
                break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (argc == 1) {
        if (conf_path == NULL) {
            conf_path = get_default_conf();
        }
    }
    // 读取conf_path 配置文件
    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (remote_num == 0) {
            remote_num = conf->remote_num;
            for (i = 0; i < remote_num; i++)
                remote_addr[i] = conf->remote_addr[i];
        }
        if (remote_port == NULL) {
            remote_port = conf->remote_port;
        }
        if (local_addr == NULL) {
            local_addr = conf->local_addr;
        }
        if (local_port == NULL) {
            local_port = conf->local_port;
        }
        if (password == NULL) {
            password = conf->password;
        }
        if (key == NULL) {
            key = conf->key;
        }
        if (method == NULL) {
            method = conf->method;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
        if (plugin == NULL) {
            plugin = conf->plugin;
        }
        if (plugin_opts == NULL) {
            plugin_opts = conf->plugin_opts;
        }
        if (reuse_port == 0) {
            reuse_port = conf->reuse_port;
        }
        if (tcp_incoming_sndbuf == 0) {
            tcp_incoming_sndbuf = conf->tcp_incoming_sndbuf;
        }
        if (tcp_incoming_rcvbuf == 0) {
            tcp_incoming_rcvbuf = conf->tcp_incoming_rcvbuf;
        }
        if (tcp_outgoing_sndbuf == 0) {
            tcp_outgoing_sndbuf = conf->tcp_outgoing_sndbuf;
        }
        if (tcp_outgoing_rcvbuf == 0) {
            tcp_outgoing_rcvbuf = conf->tcp_outgoing_rcvbuf;
        }
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
        if (mode == TCP_ONLY) {
            mode = conf->mode;
        }
        if (mtu == 0) {
            mtu = conf->mtu;
        }
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
        if (no_delay == 0) {
            no_delay = conf->no_delay;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
        if (ipv6first == 0) {
            ipv6first = conf->ipv6_first;
        }
        if (acl == 0 && conf->acl != NULL) {
            LOGI("initializing acl...");
            acl = !init_acl(conf->acl);
        }
    }

    if (remote_num == 0) {
        fprintf(stderr, "remote_num is 0\n");
        exit(EXIT_FAILURE);
    }
    // 远程端口
    if (!remote_port) {
        fprintf(stderr, "remote_port is NULL\n");
        exit(EXIT_FAILURE);
    }
#ifndef HAVE_LAUNCHD
    if (!local_port) {
        fprintf(stderr, "local_port is NULL\n");
        exit(EXIT_FAILURE);
    }
#endif
    if (!password && !key) {
        fprintf(stderr, "both password and key are NULL\n");
        exit(EXIT_FAILURE);
    }

#ifdef __MINGW32__
    winsock_init();
#endif

    /**
     * •SO_SNDBUF：TCP发送缓冲区的容量上限；
     * •SO_RCVBUF：TCP接受缓冲区的容量上限；
     */
    if (tcp_incoming_sndbuf != 0 && tcp_incoming_sndbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_sndbuf = 0;
    }

    if (tcp_incoming_sndbuf != 0) {
        LOGI("set TCP incoming connection send buffer size to %d", tcp_incoming_sndbuf);
    }

    if (tcp_incoming_rcvbuf != 0 && tcp_incoming_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_rcvbuf = 0;
    }

    if (tcp_incoming_rcvbuf != 0) {
        LOGI("set TCP incoming connection receive buffer size to %d", tcp_incoming_rcvbuf);
    }

    if (tcp_outgoing_sndbuf != 0 && tcp_outgoing_sndbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_sndbuf = 0;
    }

    if (tcp_outgoing_sndbuf != 0) {
        LOGI("set TCP outgoing connection send buffer size to %d", tcp_outgoing_sndbuf);
    }

    if (tcp_outgoing_rcvbuf != 0 && tcp_outgoing_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_rcvbuf = 0;
    }

    if (tcp_outgoing_rcvbuf != 0) {
        LOGI("set TCP outgoing connection receive buffer size to %d", tcp_outgoing_rcvbuf);
    }

    // 插件配置
    if (plugin != NULL) {
        uint16_t port = get_local_port();
        if (port == 0) {
            FATAL("failed to find a free port");
        }
        snprintf(tmp_port, 8, "%d", port);
        if (is_ipv6only(remote_addr, remote_num, ipv6first)) {
            plugin_host = "::1";
        } else {
            plugin_host = "127.0.0.1";
        }
        plugin_port = tmp_port;

#ifdef __MINGW32__
        memset(&plugin_watcher, 0, sizeof(plugin_watcher));
        plugin_watcher.port = get_local_port();
        if (plugin_watcher.port == 0) {
            LOGE("failed to assign a control port for plugin");
        }
#endif

        LOGI("plugin \"%s\" enabled", plugin);
    }

    // 加密方式
    if (method == NULL) {
        method = "chacha20-ietf-poly1305";
    }

    // 请求超时
    if (timeout == NULL) {
        timeout = "60";
    }

#ifdef HAVE_SETRLIMIT
    /*
     * no need to check the return value here since we will show
     * the user an error message if setrlimit(2) fails
     */
    if (nofile > 1024) {
        if (verbose) {
            LOGI("setting NOFILE to %d", nofile);
        }
        set_nofile(nofile);
    }
#endif

    // 本地端口
    if (local_addr == NULL) {
        if (is_ipv6only(remote_addr, remote_num, ipv6first)) {
            local_addr = "::1";
        } else {
            local_addr = "127.0.0.1";
        }
    }

    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(pid_path);
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    if (no_delay) {
        LOGI("enable TCP no-delay");
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

#ifdef __MINGW32__
    // Listen on plugin control port
    if (plugin != NULL && plugin_watcher.port != 0) {
        SOCKET fd;
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd != INVALID_SOCKET) {
            plugin_watcher.valid = 0;
            do {
                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                addr.sin_family      = AF_INET;
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                addr.sin_port        = htons(plugin_watcher.port);
                if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
                    LOGE("failed to bind plugin control port");
                    break;
                }
                if (listen(fd, 1)) {
                    LOGE("failed to listen on plugin control port");
                    break;
                }
                plugin_watcher.fd = fd;
                ev_io_init(&plugin_watcher.io, plugin_watcher_cb, fd, EV_READ);
                ev_io_start(EV_DEFAULT, &plugin_watcher.io);
                plugin_watcher.valid = 1;
            } while (0);
            if (!plugin_watcher.valid) {
                closesocket(fd);
                plugin_watcher.port = 0;
            }
        }
    }
#endif

    if (plugin != NULL) {
        int len = 0;
        size_t buf_size = 256 * remote_num;
        char *remote_str = ss_malloc(buf_size);

        snprintf(remote_str, buf_size, "%s", remote_addr[0].host);
        len = strlen(remote_str);
        for (int i = 1; i < remote_num; i++) {
            snprintf(remote_str + len, buf_size - len, "|%s", remote_addr[i].host);
            len = strlen(remote_str);
        }
        int err = start_plugin(plugin, plugin_opts, remote_str,
                               remote_port, plugin_host, plugin_port,
#ifdef __MINGW32__
                plugin_watcher.port,
#endif
                               MODE_CLIENT);
        if (err) {
            ERROR("start_plugin");
            FATAL("failed to start the plugin");
        }
    }

#ifndef __MINGW32__
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    // Setup keys
    LOGI("initializing ciphers... %s", method);
    // 初始化加密对象
    crypto = crypto_init(password, key, method);
    if (crypto == NULL)
        FATAL("failed to initialize ciphers");

    // Setup proxy context
    listen_ctx_t listen_ctx;
    listen_ctx.remote_num = 0;
    listen_ctx.remote_addr = ss_malloc(sizeof(struct sockaddr *) * remote_num);
    memset(listen_ctx.remote_addr, 0, sizeof(struct sockaddr *) * remote_num);
    for (i = 0; i < remote_num; i++) {
        char *host = remote_addr[i].host;
        char *port = remote_addr[i].port == NULL ? remote_port :
                     remote_addr[i].port;
        if (plugin != NULL) {
            host = plugin_host;
            port = plugin_port;
        }
        struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
        memset(storage, 0, sizeof(struct sockaddr_storage));
        if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        listen_ctx.remote_addr[i] = (struct sockaddr *) storage;
        ++listen_ctx.remote_num;

        if (plugin != NULL)
            break;
    }
    listen_ctx.timeout = atoi(timeout);
    listen_ctx.iface = iface;
    listen_ctx.mptcp = mptcp;

    // Setup signal handler
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
#ifndef __MINGW32__
    ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
    ev_signal_start(EV_DEFAULT, &sigchld_watcher);
#endif

    if (ss_is_ipv6addr(local_addr))
        LOGI("listening at [%s]:%s", local_addr, local_port);
    else
        LOGI("listening at %s:%s", local_addr, local_port);

    struct ev_loop *loop = EV_DEFAULT;

    if (mode != UDP_ONLY) {
        // Setup socket
        int listenfd;
#ifdef HAVE_LAUNCHD
        // Macos 系统
        listenfd = launch_or_create(local_addr, local_port);
#else
        // todo: 客户端创建和绑定端口
        listenfd = create_and_bind(local_addr, local_port);
#endif
        if (listenfd == -1) {
            FATAL("bind() error");
        }
        // 监听队列长度
        if (listen(listenfd, SOMAXCONN) == -1) {
            FATAL("listen() error");
        }
        // 设置为非阻塞
        setnonblocking(listenfd);


        listen_ctx.fd = listenfd;

        // TODO::  初始化文件变更监听 ， 处理请求
        // io观察者，方法，文件链接标识， 读操作
        ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
        ev_io_start(loop, &listen_ctx.io);
    }

    // Setup UDP
    if (mode != TCP_ONLY) {
        LOGI("udprelay enabled");
        char *host = remote_addr[0].host;
        char *port = remote_addr[0].port == NULL ? remote_port : remote_addr[0].port;
        struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
        memset(storage, 0, sizeof(struct sockaddr_storage));
        if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        struct sockaddr *addr = (struct sockaddr *) storage;
        udp_fd = init_udprelay(local_addr, local_port, addr,
                               get_sockaddr_len(addr), mtu, crypto, listen_ctx.timeout, iface);
    }

#ifdef HAVE_LAUNCHD
    if (local_port == NULL)
        LOGI("listening through launchd");
    else
#endif

#ifndef __MINGW32__
    // setuid
    if (user != NULL && !run_as(user)) {
        FATAL("failed to switch user");
    }

    if (geteuid() == 0) {
        LOGI("running from root user");
    }
#endif

    // Init connections
    cork_dllist_init(&connections);

    // Enter the loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    if (plugin != NULL) {
        stop_plugin();
    }

    if (mode != UDP_ONLY) {
        ev_io_stop(loop, &listen_ctx.io);
        free_connections(loop);

        for (i = 0; i < listen_ctx.remote_num; i++) ss_free(listen_ctx.remote_addr[i]);
        ss_free(listen_ctx.remote_addr);
    }

    if (mode != TCP_ONLY) {
        free_udprelay();
    }

#ifdef __MINGW32__
    if (plugin_watcher.valid) {
        closesocket(plugin_watcher.fd);
    }

    winsock_cleanup();
#endif

    return ret_val;
}

#else

int
_start_ss_local_server(profile_t profile, ss_local_callback callback, void *udata)
{
    srand(time(NULL));

    char *remote_host = profile.remote_host;
    char *local_addr  = profile.local_addr;
    char *method      = profile.method;
    char *password    = profile.password;
    char *log         = profile.log;
    int remote_port   = profile.remote_port;
    int local_port    = profile.local_port;
    int timeout       = profile.timeout;
    int mtu           = 0;
    int mptcp         = 0;

    mode      = profile.mode;
    fast_open = profile.fast_open;
    verbose   = profile.verbose;
    mtu       = profile.mtu;
    mptcp     = profile.mptcp;

    char local_port_str[16];
    char remote_port_str[16];
    sprintf(local_port_str, "%d", local_port);
    sprintf(remote_port_str, "%d", remote_port);

#ifdef __MINGW32__
    winsock_init();
#endif

    USE_LOGFILE(log);

    if (profile.acl != NULL) {
        LOGI("initializing acl...");
        acl = !init_acl(profile.acl);
    }

    if (local_addr == NULL) {
        local_addr = "127.0.0.1";
    }

#ifndef __MINGW32__
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
#ifndef __MINGW32__
    ev_signal_init(&sigusr1_watcher, signal_cb, SIGUSR1);
    ev_signal_start(EV_DEFAULT, &sigusr1_watcher);
#endif

    // Setup keys
    LOGI("initializing ciphers... %s", method);
    crypto = crypto_init(password, NULL, method);
    if (crypto == NULL)
        FATAL("failed to init ciphers");

    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(struct sockaddr_storage));
    if (get_sockaddr(remote_host, remote_port_str, &storage, 0, ipv6first) == -1) {
        return -1;
    }

    // Setup proxy context
    struct ev_loop *loop = EV_DEFAULT;

    struct sockaddr *remote_addr_tmp[MAX_REMOTE_NUM];
    listen_ctx_t listen_ctx;
    listen_ctx.remote_num     = 1;
    listen_ctx.remote_addr    = remote_addr_tmp;
    listen_ctx.remote_addr[0] = (struct sockaddr *)(&storage);
    listen_ctx.timeout        = timeout;
    listen_ctx.iface          = NULL;
    listen_ctx.mptcp          = mptcp;

    if (ss_is_ipv6addr(local_addr))
        LOGI("listening at [%s]:%s", local_addr, local_port_str);
    else
        LOGI("listening at %s:%s", local_addr, local_port_str);

    if (mode != UDP_ONLY) {
        // Setup socket
        int listenfd;
        listenfd = create_and_bind(local_addr, local_port_str);
        if (listenfd == -1) {
            ERROR("bind()");
            return -1;
        }
        if (listen(listenfd, SOMAXCONN) == -1) {
            ERROR("listen()");
            return -1;
        }
        setnonblocking(listenfd);

        listen_ctx.fd = listenfd;

        ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
        ev_io_start(loop, &listen_ctx.io);
    }

    // Setup UDP
    if (mode != TCP_ONLY) {
        LOGI("udprelay enabled");
        struct sockaddr *addr = (struct sockaddr *)(&storage);
        udp_fd = init_udprelay(local_addr, local_port_str, addr,
                               get_sockaddr_len(addr), mtu, crypto, timeout, NULL);
    }

    // Init connections
    cork_dllist_init(&connections);

    if (callback) {
        callback(listen_ctx.fd, udp_fd, udata);
    }

    // Enter the loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    if (mode != UDP_ONLY) {
        ev_io_stop(loop, &listen_ctx.io);
        free_connections(loop);
        close(listen_ctx.fd);
    }

    if (mode != TCP_ONLY) {
        free_udprelay();
    }

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    return ret_val;
}

int
start_ss_local_server(profile_t profile)
{
    return _start_ss_local_server(profile, NULL, NULL);
}

int
start_ss_local_server_with_callback(profile_t profile, ss_local_callback callback, void *udata)
{
    return _start_ss_local_server(profile, callback, udata);
}

#endif
