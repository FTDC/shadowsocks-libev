/*
 * netutils.c - Network utilities
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

#include <math.h>

#include <libcork/core.h>

#ifdef HAVE_CONFIG_H

#include "config.h"

#endif

#ifndef __MINGW32__

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)

#include <net/if.h>
#include <sys/ioctl.h>

#define SET_INTERFACE
#endif

#include "netutils.h"
#include "utils.h"
#include "acl.h"
#include "crypto.h"

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

extern int verbose;

static const char valid_label_bytes[] =
        "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

int
set_reuseport(int socket) {
    int opt = 1;
    return setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
}

/**
 * 获取 sockaddr_in 大小
 * @param addr socket address
 * @return
 */
size_t
get_sockaddr_len(struct sockaddr *addr) {
    if (addr->sa_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}

#ifdef SET_INTERFACE

int
setinterface(int socket_fd, const char *interface_name) {
    struct ifreq interface;
    memset(&interface, 0, sizeof(struct ifreq));
    strncpy(interface.ifr_name, interface_name, IFNAMSIZ - 1);
    int res = setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, &interface,
                         sizeof(struct ifreq));
    return res;
}

#endif

int
parse_local_addr(struct sockaddr_storage *storage_v4,
                 struct sockaddr_storage *storage_v6,
                 const char *host) {
    if (host != NULL) {
        struct cork_ip ip;
        if (cork_ip_init(&ip, host) != -1) {
            if (ip.version == 4) {
                memset(storage_v4, 0, sizeof(struct sockaddr_storage));
                struct sockaddr_in *addr = (struct sockaddr_in *) storage_v4;
                inet_pton(AF_INET, host, &addr->sin_addr);
                addr->sin_family = AF_INET;
                LOGI("binding to outbound IPv4 addr: %s", host);
                return AF_INET;
            } else if (ip.version == 6) {
                memset(storage_v6, 0, sizeof(struct sockaddr_storage));
                struct sockaddr_in6 *addr = (struct sockaddr_in6 *) storage_v6;
                inet_pton(AF_INET6, host, &addr->sin6_addr);
                addr->sin6_family = AF_INET6;
                LOGI("binding to outbound IPv6 addr: %s", host);
                return AF_INET6;
            }
        }
    }
    return 0;
}

int
bind_to_addr(struct sockaddr_storage *storage,
             int socket_fd) {
    if (storage->ss_family == AF_INET) {
        return bind(socket_fd, (struct sockaddr *) storage, sizeof(struct sockaddr_in));
    } else if (storage->ss_family == AF_INET6) {
        return bind(socket_fd, (struct sockaddr *) storage, sizeof(struct sockaddr_in6));
    }
    return -1;
}

ssize_t
get_sockaddr(char *host, char *port,
             struct sockaddr_storage *storage, int block,
             int ipv6first) {
    struct cork_ip ip;
    if (cork_ip_init(&ip, host) != -1) {
        if (ip.version == 4) {
            struct sockaddr_in *addr = (struct sockaddr_in *) storage;
            addr->sin_family = AF_INET;
            inet_pton(AF_INET, host, &(addr->sin_addr));
            if (port != NULL) {
                addr->sin_port = htons(atoi(port));
            }
        } else if (ip.version == 6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *) storage;
            addr->sin6_family = AF_INET6;
            inet_pton(AF_INET6, host, &(addr->sin6_addr));
            if (port != NULL) {
                addr->sin6_port = htons(atoi(port));
            }
        }
        return 0;
    } else {
#ifdef __ANDROID__
        extern int vpn;
        assert(!vpn);   // protecting DNS packets isn't supported yet
#endif
        struct addrinfo hints;
        struct addrinfo *result, *rp;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
        hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

        int err = getaddrinfo(host, port, &hints, &result);

        if (err != 0) {
            LOGE("getaddrinfo: %s", gai_strerror(err));
            return -1;
        }

        int prefer_af = ipv6first ? AF_INET6 : AF_INET;
        for (rp = result; rp != NULL; rp = rp->ai_next)
            if (rp->ai_family == prefer_af) {
                if (rp->ai_family == AF_INET)
                    memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in));
                else if (rp->ai_family == AF_INET6)
                    memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in6));
                break;
            }

        if (rp == NULL) {
            for (rp = result; rp != NULL; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET)
                    memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in));
                else if (rp->ai_family == AF_INET6)
                    memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in6));
                break;
            }
        }

        if (rp == NULL) {
            LOGE("failed to resolve remote addr");
            return -1;
        }

        freeaddrinfo(result);
        return 0;
    }

    return -1;
}

int
sockaddr_cmp(struct sockaddr_storage *addr1,
             struct sockaddr_storage *addr2, socklen_t len) {
    struct sockaddr_in *p1_in = (struct sockaddr_in *) addr1;
    struct sockaddr_in *p2_in = (struct sockaddr_in *) addr2;
    struct sockaddr_in6 *p1_in6 = (struct sockaddr_in6 *) addr1;
    struct sockaddr_in6 *p2_in6 = (struct sockaddr_in6 *) addr2;
    if (p1_in->sin_family < p2_in->sin_family)
        return -1;
    if (p1_in->sin_family > p2_in->sin_family)
        return 1;
    /* compare ip4 */
    if (p1_in->sin_family == AF_INET) {
        /* just order it, ntohs not required */
        if (p1_in->sin_port < p2_in->sin_port)
            return -1;
        if (p1_in->sin_port > p2_in->sin_port)
            return 1;
        return memcmp(&p1_in->sin_addr, &p2_in->sin_addr, INET_SIZE);
    } else if (p1_in6->sin6_family == AF_INET6) {
        /* just order it, ntohs not required */
        if (p1_in6->sin6_port < p2_in6->sin6_port)
            return -1;
        if (p1_in6->sin6_port > p2_in6->sin6_port)
            return 1;
        return memcmp(&p1_in6->sin6_addr, &p2_in6->sin6_addr,
                      INET6_SIZE);
    } else {
        /* eek unknown type, perform this comparison for sanity. */
        return memcmp(addr1, addr2, len);
    }
}

int
sockaddr_cmp_addr(struct sockaddr_storage *addr1,
                  struct sockaddr_storage *addr2, socklen_t len) {
    struct sockaddr_in *p1_in = (struct sockaddr_in *) addr1;
    struct sockaddr_in *p2_in = (struct sockaddr_in *) addr2;
    struct sockaddr_in6 *p1_in6 = (struct sockaddr_in6 *) addr1;
    struct sockaddr_in6 *p2_in6 = (struct sockaddr_in6 *) addr2;
    if (p1_in->sin_family < p2_in->sin_family)
        return -1;
    if (p1_in->sin_family > p2_in->sin_family)
        return 1;
    if (verbose) {
        LOGI("sockaddr_cmp_addr: sin_family equal? %d", p1_in->sin_family == p2_in->sin_family);
    }
    /* compare ip4 */
    if (p1_in->sin_family == AF_INET) {
        return memcmp(&p1_in->sin_addr, &p2_in->sin_addr, INET_SIZE);
    } else if (p1_in6->sin6_family == AF_INET6) {
        return memcmp(&p1_in6->sin6_addr, &p2_in6->sin6_addr,
                      INET6_SIZE);
    } else {
        /* eek unknown type, perform this comparison for sanity. */
        return memcmp(addr1, addr2, len);
    }
}

int
validate_hostname(const char *hostname, const int hostname_len) {
    if (hostname == NULL)
        return 0;

    if (hostname_len < 1 || hostname_len > 255)
        return 0;

    if (hostname[0] == '.')
        return 0;

    const char *label = hostname;
    while (label < hostname + hostname_len) {
        size_t label_len = hostname_len - (label - hostname);
        char *next_dot = strchr(label, '.');
        if (next_dot != NULL)
            label_len = next_dot - label;

        if (label + label_len > hostname + hostname_len)
            return 0;

        if (label_len > 63 || label_len < 1)
            return 0;

        if (label[0] == '-' || label[label_len - 1] == '-')
            return 0;

        if (strspn(label, valid_label_bytes) < label_len)
            return 0;

        label += label_len + 1;
    }

    return 1;
}

int
is_ipv6only(ss_addr_t *servers, size_t server_num, int ipv6first) {
    int i;
    for (i = 0; i < server_num; i++) {
        struct sockaddr_storage storage;
        memset(&storage, 0, sizeof(struct sockaddr_storage));
        if (get_sockaddr(servers[i].host, servers[i].port, &storage, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        if (storage.ss_family != AF_INET6) {
            return 0;
        }
    }
    return 1;
}

int
remote_recv_cmd(buffer_t *abuf) {
    int ret = 0;
    int cmdlen = 0;
    int cmd = -1;

    char *retcmd = abuf->data;
    //add by heron: 检测是否收到指令
    if (retcmd[0] == '\xf0' && retcmd[1] == '\xf1' && retcmd[2] == '\xf2' && retcmd[3] == '\xf3' &&
        retcmd[4] == '\xf4' && retcmd[5] == '\xf5' && retcmd[6] == '\xf6') {
        cmdlen = load16_be(abuf->data + 8);
        cmd = retcmd[7] + 0;
        LOGE("---msg---cmd:%d, cmdlen:%d--len=" SSIZE_FMT, cmd, cmdlen, abuf->len);

        LOGE("---msg-recv---0x%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", abuf->data[0], abuf->data[1],
             abuf->data[2],
             abuf->data[3], abuf->data[4], abuf->data[5], abuf->data[6], abuf->data[7], abuf->data[8], abuf->data[9]);

#ifdef LIB_ONLY
        ret=1;
#else
        switch (cmd)//i=7
        {
            case 0x00://xroute_handshake_failed
#ifdef __ANDROID__
                if(client_msg_fd) {
                   send(client_msg_fd, off_line, strlen(off_line), 0);
               }
#endif
#ifdef __mips__
                LOGE("---msg---cmd---:%s", off_line);
               executeCMD("uci set ss_login.@login[0].link_status=","您的账号已在异地登录，请修改密码或重新登录。");
#endif
//                LOGI("---msg---cmd---:%s", off_line);//win
                ret = 1;
                break;
            case 0x01://xroute_tls_handshake_failed
#ifdef __ANDROID__
                if(client_msg_fd) {
                   send(client_msg_fd, need_CA, strlen(need_CA), 0);
               }
#endif
#ifdef __mips__
                LOGE("---msg---cmd---:%s", need_CA);
               executeCMD("uci set ss_login.@login[0].link_status=","请安装装证书！");
#endif

//                LOGI("---msg---cmd---:%s", need_CA);//win
                ret = 1;
                break;
            case 0x02://xroute_level_not_match_server
#ifdef __ANDROID__
                if(client_msg_fd) {
                   send(client_msg_fd, LevelNotMatch, strlen(LevelNotMatch), 0);
               }
#endif
#ifdef __mips__
                LOGE("---msg---cmd---:%s", LevelNotMatch);
               executeCMD("uci set ss_login.@login[0].link_status=","用户等级不匹配，请联系服务商。");
#endif
//                LOGI("---msg---cmd---:%s", LevelNotMatch);//win
                ret = 1;
                break;

            case 0x03://xroute_user_service_expired
#ifdef __ANDROID__
                if(client_msg_fd) {
                   send(client_msg_fd, service_expired, strlen(service_expired), 0);
               }
#endif
#ifdef __mips__
                LOGE("---msg---cmd---:%s", service_expired);
               executeCMD("uci set ss_login.@login[0].link_status=","服务到期，请续费！");
#endif

//                LOGI("---msg---cmd---:%s", service_expired);//win
                ret = 1;
                break;
            case 0x04://dns /* "{\"www.baidu.com\":\"192.168.88.71\",\"www.google.com\":\"114.114.114.114\"}" */
            {
                char dnsdata[1024] = {0};
                if (cmdlen)
                    memcpy(dnsdata, abuf->data + 10, cmdlen);
                LOGI("---msg---cmd---cmdlen=%d,---dns:%s", cmdlen, dnsdata);

                //int ret = read_dnsbuf(dnsdata);
                //if(ret)
                //    LOGI("---msg---cmd---:error!!!");
                LOGE("---msg-cmd---dns:%s", dnsdata);
                ret = 2;
            }
                break;
            case 0x05://xroute_vpn_service_restart
#ifdef __ANDROID__
                if(client_msg_fd) {
                   send(client_msg_fd, service_restart, strlen(service_restart), 0);
               }
#endif
#ifdef __mips__
                LOGE("---msg---cmd---:%s", service_restart);
               executeCMD("uci set ss_login.@login[0].link_status=","长期未使用，需要重连！");
#endif

//                LOGI("---msg---cmd---:%s", service_restart);
                ret = 1;
                break;
            case 0x06://xroute_services_domain_update
            {
                char version[128] = {0};
                char cmddata[128] = {0};
                if (cmdlen)
                    memcpy(cmddata, retcmd + 10, cmdlen);
                //LOGI("---msg---cmddata:%s", cmddata);
//                sprintf(version, "---msg---cmd---:%s:%s", domain_update, cmddata);
#ifdef __ANDROID__
                if(client_msg_fd) {
                        send(client_msg_fd, version, strlen(version), 0);
                    }
#endif
//                LOGI("---msg---cmd---:%s:%s", domain_update, cmddata);
            }
                ret = 2;
                break;
            default: {
                LOGE("---msg---cmd---:error!!!");
                ret = 0;
            }
                break;
        }

        if (ret) {
            cmdlen += 10;
            //LOGI("---msg---cmd---i=%d,---len:%d", i, cmdlen);
            if (cmdlen) {
                memmove(abuf->data, abuf->data + cmdlen,
                        abuf->len - cmdlen);
            }
            abuf->len -= cmdlen;
            if (verbose) {
                LOGI("---cmd=%d---all-len:%d, abuf->len=" SIZE_FMT, cmd, cmdlen, abuf->len);
            }
        }
#endif
    }

    return ret;
}

