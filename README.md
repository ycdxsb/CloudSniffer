# CloudSniffer

一款基于Scapy和PyQt5的网络嗅探工具



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
- IP所在地统计

**其他功能**

- 嗅探前过滤、嗅探后过滤
- html内容提取



**安装使用**

```shell
$ git clone https://github.com/ycdxsb/CloudSniffer.git
$ cd ./CloudSniffer
$ pip3 install requirements.txt
$ python3 CloudSniffer.py
```





