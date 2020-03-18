# CloudSniffer

一款基于Scapy和PyQt5的网络嗅探工具

#### 功能

**基本功能**：

- 网卡选择
- 开始、停止抓包
- 清除数据
- 保存数据
- 读取数据
- 退出程序
- 流量包基本信息显示
- 协议分析
- hexdump内容



**统计功能**

- 流量协议统计（帧数、字节数）

- 流入流量统计（帧数、字节数）
- 流出流量统计（帧数、字节数）
- 流量时间统计（字节数）
- IP所在地查询

**其他功能**

- 嗅探前过滤、嗅探后过滤
- html内容提取
- 日志记录



#### 效果展示

**基本界面**

![basic](https://github.com/ycdxsb/CloudSniffer/blob/master/images/basic.png)

![basic.gif](https://github.com/ycdxsb/CloudSniffer/blob/master/images/basic.gif)

**统计功能**

![statistics](https://github.com/ycdxsb/CloudSniffer/blob/master/images/statistics.png)

![statistics.gif](https://github.com/ycdxsb/CloudSniffer/blob/master/images/statistics.gif)

**提取html内容**

![extractHTML](https://github.com/ycdxsb/CloudSniffer/blob/master/images/extractHTML.png)

![extractHTML.gif](https://github.com/ycdxsb/CloudSniffer/blob/master/images/extractHTML.gif)



#### 安装使用

```shell
$ git clone https://github.com/ycdxsb/CloudSniffer.git
$ cd ./CloudSniffer
$ pip3 install requirements.txt
$ python3 CloudSniffer.py
```



#### 依赖库

```
dpkt==1.9.2
geoip2==2.9.0
pyecharts==1.7.0
PyQt5==5.14.1
PyQt5-sip==12.7.1
PyQtWebEngine==5.14.0
scapy==2.4.3
scapy-http==1.8.2
pypcap==1.2.3
```



#### 参考

- [scapy-http](https://github.com/invernizzi/scapy-http)
- [Pcap-Analyser](https://github.com/HatBoy/Pcap-Analyzer)









