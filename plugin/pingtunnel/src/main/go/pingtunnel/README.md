# Pingtunnel

[<img src="https://img.shields.io/github/license/esrrhs/pingtunnel">](https://github.com/esrrhs/pingtunnel)
[<img src="https://img.shields.io/github/languages/top/esrrhs/pingtunnel">](https://github.com/esrrhs/pingtunnel)
[![Go Report Card](https://goreportcard.com/badge/github.com/esrrhs/pingtunnel)](https://goreportcard.com/report/github.com/esrrhs/pingtunnel)
[<img src="https://img.shields.io/github/v/release/esrrhs/pingtunnel">](https://github.com/esrrhs/pingtunnel/releases)
[<img src="https://img.shields.io/github/downloads/esrrhs/pingtunnel/total">](https://github.com/esrrhs/pingtunnel/releases)
[<img src="https://img.shields.io/docker/pulls/esrrhs/pingtunnel">](https://hub.docker.com/repository/docker/esrrhs/pingtunnel)
[<img src="https://img.shields.io/github/workflow/status/esrrhs/pingtunnel/Go">](https://github.com/esrrhs/pingtunnel/actions)

pingtunnel 是把 tcp/udp/sock5 流量伪装成 icmp 流量进行转发的工具

[Readme EN](./README_EN.md)

## 注意：本工具只是用作学习研究，请勿用于非法用途！！！

![image](network.jpg)

## 使用

### 安装服务端

-   首先准备好一个具有公网 ip 的服务器，假定域名或者公网 ip 是www.yourserver.com
-   从[releases](https://github.com/esrrhs/pingtunnel/releases)下载对应的安装包，如 pingtunnel_linux64.zip，然后解压，以**root**权限执行

```
sudo wget (最新release的下载链接)
sudo unzip pingtunnel_linux64.zip
sudo ./pingtunnel -type server
```

-   (可选)关闭系统默认的 ping

```
echo 1 >/proc/sys/net/ipv4/icmp_echo_ignore_all
```

### 安装 GUI 客户端(新手推荐)

-   从[pingtunnel-qt](https://github.com/esrrhs/pingtunnel-qt)下载 qt 的 gui 版本
-   双击 exe 运行，修改 server（如www.yourserver.com）、listen port（如 1080），勾上 sock5，其他设置默认即可，然后点击*GO*
-   一切正常，界面上会有 ping 值显示，然后可点击 X 隐藏到状态栏
-   设置浏览器的 sock5 代理到 127.0.0.1:1080，如果连不上网，出现 socks version not supported 错误日志，说明浏览器的代理不是 socks5 代理。如果提示非安全连接，说明 dns 有问题，勾上浏览器的【使用 socks5 代理 DNS 查询】

![image](qtrun.jpg)

### 安装客户端(高玩推荐)

-   从[releases](https://github.com/esrrhs/pingtunnel/releases)下载对应的安装包，如 pingtunnel_windows64.zip，解压
-   然后用**管理员权限**运行，不同的转发功能所对应的命令如下
-   如果看到有 ping pong 的 log，说明连接正常

#### 转发 sock5

```
pingtunnel.exe -type client -l :4455 -s www.yourserver.com -sock5 1
```

#### 转发 tcp

```
pingtunnel.exe -type client -l :4455 -s www.yourserver.com -t www.yourserver.com:4455 -tcp 1
```

#### 转发 udp

```
pingtunnel.exe -type client -l :4455 -s www.yourserver.com -t www.yourserver.com:4455
```

### Docker(高玩推荐)
也可直接用docker启动，更方便。参数同上
-   server:
```
docker run --name pingtunnel-server -d --privileged --network host --restart=always esrrhs/pingtunnel ./pingtunnel -type server -key 123456
```
-   client:
```
docker run --name pingtunnel-client -d --restart=always -p 1080:1080 esrrhs/pingtunnel ./pingtunnel -type client -l :1080 -s www.yourserver.com -sock5 1 -key 123456
```

## 效果

下载 centos 镜像 [centos mirror](http://mirrors.ocf.berkeley.edu/centos/8.2.2004/isos/x86_64/CentOS-8.2.2004-x86_64-dvd1.iso)，对比如下

|        | wget     | ss       | kcp     | pingtunnel |
| ------ | -------- | -------- | ------- | ---------- |
| 阿里云 | 26.6KB/s | 31.8KB/s | 606KB/s | 5.64MB/s   |
