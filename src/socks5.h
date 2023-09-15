/*
 * socks5.h - Define SOCKS5's header
 *
 * Copyright (C) 2013, clowwindy <clowwindy42@gmail.com>
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

#ifndef _SOCKS5_H
#define _SOCKS5_H

#define SVERSION 0x05
#define METHOD_NOAUTH 0x00
#define METHOD_UNACCEPTABLE 0xff

// see also: https://www.ietf.org/rfc/rfc1928.txt
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

#define SOCKS5_REP_SUCCEEDED 0x00
#define SOCKS5_REP_GENERAL 0x01
#define SOCKS5_REP_CONN_DISALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_HOST_UNREACHABLE 0x04
#define SOCKS5_REP_CONN_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED 0x06
#define SOCKS5_REP_CMD_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRTYPE_NOT_SUPPORTED 0x08
#define SOCKS5_REP_FF_UNASSIGNED 0x09


// 可选认证方法请求
//        选择一种认证方法
//发送用户名和密码
//        验证身份成功
//浏览器
//        Socks5代理服务器
//认证阶段完成
//  https://www.ietf.org/rfc/rfc1928.txt

// 认证方法请求，方法数和支持的方法
//                   +----+----------+----------+
//                   |VER | NMETHODS | METHODS  |
//                   +----+----------+----------+
//                   | 1  |    1     | 1 to 255 |
//                   +----+----------+----------+
//  VERSION SOCKS协议版本，目前固定0x05
//  METHODS_COUNT 客户端支持的认证方法数量
//  METHODS… 客户端支持的认证方法，每个方法占用1个字节
//
//  METHOD定义
//      0x00 不需要认证（常用）
//      0x01 GSSAPI认证
//      0x02 账号密码认证（常用）
//      0x03 - 0x7F IANA分配
//      0x80 - 0xFE 私有方法保留
//      0xFF 无支持的认证方法
struct method_select_request {
    unsigned char ver;  // socket version
    unsigned char nmethods; // 认证方法数
    unsigned char methods[0]; // 支持的方法
} __attribute__((packed, aligned(1)));

//  服务端返回选择的认证方法
//                         +----+--------+
//                         |VER | METHOD |
//                         +----+--------+
//                         | 1  |   1    |
//                         +----+--------+
// VERSION SOCKS协议版本，目前固定0x05
//  METHOD 本次连接所用的认证方法，上例中为无需认证

struct method_select_response {
    unsigned char ver; // socket 协议版本 0x05
    unsigned char method; // 支持的方法
} __attribute__((packed, aligned(1)));

//  客户端发送请求
//
//        +----+-----+-------+------+----------+----------+
//        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//        +----+-----+-------+------+----------+----------+
//        | 1  |  1  | X'00' |  1   | Variable |    2     |
//        +----+-----+-------+------+----------+----------+
//
//VERSION SOCKS协议版本，固定0x05
//  CMD
//             o  CONNECT X'01' tpc 代理
//             o  BIND X'02' tpc 代理
//             o  UDP ASSOCIATE X'03' udp 代理
//  ATYP   address type of following address
//             o  IP V4 address: X'01'
//             o  DOMAINNAME: X'03'
//             o  IP V6 address: X'04'
//RSV 保留字段  值为0x00
//RESPONSE 响应命令
//      0x00 代理服务器连接目标服务器成功
//      0x01 代理服务器故障
//      0x02 代理服务器规则集不允许连接
//      0x03 网络无法访问
//      0x04 目标服务器无法访问（主机名无效）
//      0x05 连接目标服务器被拒绝
//      0x06 TTL已过期
//      0x07 不支持的命令
//      0x08 不支持的目标服务器地址类型
//      0x09 - 0xFF 未分配
//DST.ADDR 目标服务器地址，一个可变长度的值
//DST.PORT 目标服务器端口
struct socks5_request {
    unsigned char ver; // SOCKS协议版本，固定0x05
    unsigned char cmd; // CMD CONNECT X'01', o  BIND X'02',  UDP ASSOCIATE X'03'
    unsigned char rsv; // 保留字段  值为0x00
    unsigned char atyp; // IP V4 address: X'01', DOMAINNAME: X'03', IP V6 address: X'04'
} __attribute__((packed, aligned(1)));

//        +----+-----+-------+------+----------+----------+
//        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//        +----+-----+-------+------+----------+----------+
//        | 1  |  1  | X'00' |  1   | Variable |    2     |
//        +----+-----+-------+------+----------+----------+

//VERSION SOCKS协议版本，固定0x05
//RESPONSE 响应命令
//      0x00 代理服务器连接目标服务器成功
//      0x01 代理服务器故障
//      0x02 代理服务器规则集不允许连接
//      0x03 网络无法访问
//      0x04 目标服务器无法访问（主机名无效）
//      0x05 连接目标服务器被拒绝
//      0x06 TTL已过期
//      0x07 不支持的命令
//      0x08 不支持的目标服务器地址类型
//      0x09 - 0xFF 未分配
//RSV 保留字段  值为0x00
//  ATYP   address type of following address
//             o  IP V4 address: X'01'
//             o  DOMAINNAME: X'03'
//             o  IP V6 address: X'04'
//BND.ADDR 代理服务器连接目标服务器成功后的代理服务器IP
//BND.PORT 代理服务器连接目标服务器成功后的代理服务器端口
struct socks5_response {
    unsigned char ver; // SOCKS协议版本，固定0x05
    unsigned char rep; //  RESPONSE 响应命令     0x00 代理服务器连接目标服务器成功
    unsigned char rsv; // 保留字段  值为0x00
    unsigned char atyp; //  IP V4 address: X'01', DOMAINNAME: X'03', IP V6 address: X'04'
} __attribute__((packed, aligned(1)));

#endif // _SOCKS5_H
