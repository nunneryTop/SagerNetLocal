# Brook

[English](README.md)

[![Build Status](https://travis-ci.org/txthinking/brook.svg?branch=master)](https://travis-ci.org/txthinking/brook)
[![文档](https://img.shields.io/badge/%E6%95%99%E7%A8%8B-%E6%96%87%E6%A1%A3-yellow.svg)](https://txthinking.github.io/brook/#/zh-cn/)
[![博客](https://img.shields.io/badge/%E6%95%99%E7%A8%8B-%E5%B9%BB%E7%81%AF%E7%89%87-blueviolet.svg)](https://talks.txthinking.com)
[![视频](https://img.shields.io/badge/%E6%95%99%E7%A8%8B-%E8%A7%86%E9%A2%91-red.svg)](https://www.youtube.com/txthinking)
[![开源协议: GPL v3](https://img.shields.io/badge/%E5%BC%80%E6%BA%90%E5%8D%8F%E8%AE%AE-GPL%20v3-yellow.svg)](http://www.gnu.org/licenses/gpl-3.0)
[![捐赠](https://img.shields.io/badge/%E6%94%AF%E6%8C%81-%E6%8D%90%E8%B5%A0-ff69b4.svg)](https://www.txthinking.com/opensource-support.html)

<p align="center">
    <img style="float:right;" src="https://txthinking.github.io/brook/_static/brook.png" alt="Brook"/>
</p>

---

**v20210601**

-   [CLI] \$ brook map 支持 brook server/wsserver/wssserver
-   [CLI] \$ brook dns 支持 brook server/wsserver/wssserver
-   [CLI] \$ brook tproxy 支持 brook server/wsserver/wssserver
-   [GUI] OpenWrt 支持 brook server/wsserver/wssserver
-   [Document](https://txthinking.github.io/brook/)
-   [论坛](https://github.com/txthinking/brook/discussions)

---

## 什么是 Brook

Brook 是一个跨平台的强加密无特征的代理软件. 偏爱 KISS 哲学.

[查看文档](https://txthinking.github.io/brook/#/zh-cn/?id=%e4%bb%80%e4%b9%88%e6%98%afcli%e5%92%8cgui)

### 安装 CLI (命令行版本)

```
$ curl -L https://github.com/txthinking/brook/releases/latest/download/brook_linux_amd64 -o /usr/bin/brook
$ chmod +x /usr/bin/brook
```

[查看文档](https://txthinking.github.io/brook/#/zh-cn/install-cli)

### 安装 GUI (图形客户端)

[查看文档](https://txthinking.github.io/brook/#/zh-cn/install-gui-client)

## 使用

[查看文档](https://txthinking.github.io/brook/#/zh-cn/)

```
NAME:
   Brook - A cross-platform strong encryption and not detectable proxy

USAGE:
   brook [global options] command [command options] [arguments...]

VERSION:
   20210601

AUTHOR:
   Cloud <cloud@txthinking.com>

COMMANDS:
   server        Run as brook server, both TCP and UDP
   servers       Run as multiple brook servers
   client        Run as brook client, both TCP and UDP, to start a socks5 proxy, [src <-> socks5 <-> $ brook client <-> $ brook server <-> dst], [works with
$ brook server]
   map           Run as mapping, both TCP and UDP, this means access [from address] is equal to [to address], [src <-> from address <-> $ brook <-> to addres
s], works with $ brook server/wsserver/wssserver
   dns           Run as DNS server, both TCP and UDP, [src <-> $ brook dns <-> $ brook <-> dns server] or [src <-> $ brook dns <-> dns server for bypass], wo
rks with $ brook server/wsserver/wssserver
   tproxy        Run as transparent proxy, both TCP and UDP, only works on Linux, [src <-> $ brook tproxy <-> $ brook <-> dst], works with $ brook server/wss
erver/wssserver
   wsserver      Run as brook wsserver, both TCP and UDP, it will start a standard http server and websocket server
   wssserver     Run as brook wssserver, both TCP and UDP, it will start a standard https server and websocket server
   wsclient      Run as brook wsclient, both TCP and UDP, to start a socks5 proxy, [src <-> socks5 <-> $ brook wsclient <-> $ brook wsserver <-> dst], [works
 with $ brook wsserver]
   wssclient     Run as brook wssclient, both TCP and UDP, to start a socks5 proxy, [src <-> socks5 <-> $ brook wssclient <-> $ brook wssserver <-> dst], [wo
rks with $ brook wssserver]
   link          Print brook link
   qr            Print brook server QR code
   connect       Connect via standard sharing link (brook server & brook wsserver & brook wssserver)
   relay         Run as standalone relay, both TCP and UDP, this means access [listen address] is equal to access [to address], [src <-> listen address <-> t
o address]
   relays        Run as multiple standalone relays
   socks5        Run as standalone standard socks5 server, both TCP and UDP
   socks5tohttp  Convert socks5 to http proxy, [src <-> listen address(http proxy) <-> socks5 address <-> dst]
   hijackhttps   Hijack domains and assume is TCP/TLS/443. Requesting these domains from anywhere in the system will be hijacked . [src <-> $ brook hijackhtt
ps <-> socks5 server] or [src <-> direct]
   pac           Run as PAC server or save PAC to file
   howto         Print some useful tutorial resources
   help, h       Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug, -d               Enable debug (default: false)
   --listen value, -l value  Listen address for debug (default: ":6060")
   --help, -h                show help (default: false)
   --version, -v             print the version (default: false)

COPYRIGHT:
   https://github.com/txthinking/brook
```

[文档](https://txthinking.github.io/brook/#/zh-cn/)

## 贡献

请先阅读 [CONTRIBUTING.md](https://github.com/txthinking/brook/blob/master/.github/CONTRIBUTING.md)

## 开源协议

基于 GPLv3 协议开源
