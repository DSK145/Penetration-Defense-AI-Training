# 声明 Python 脚本的解释器路径，告诉系统用 /usr/bin/python 来执行该脚本
import sys
# 导入 sys 模块，用于处理命令行参数、程序退出等系统相关功能
from scapy.all import *
# 从 Scapy 库中导入所有内容，Scapy 是用于网络数据包操作、发送、解析等的库
import time
# 导入 time 模块，用于实现时间相关功能，比如延时

iface = "eth0"
print("要网卡，默认名 eth0")
# 初始化网络接口为 eth0，后续可能用于指定发送数据包的网卡
if len(sys.argv) >= 2:
    # 判断命令行参数的数量，如果大于等于 2（脚本名是第一个参数，这里判断是否有第二个及以上参数 ）
    iface = sys.argv[1]
    # 将网络接口重新赋值为命令行传入的第一个参数（索引为 1，因为索引 0 是脚本名 ）

while (1):
    # 开始一个无限循环，让后续发包操作持续进行
    packet = Ether(src=RandMAC(), dst=RandMAC()) / IP(src=RandIP(), dst=RandIP()) / ICMP()
    # 构造网络数据包：
    # Ether 部分：用 RandMAC() 生成随机的源 MAC 地址和目的 MAC 地址，构建以太网头部
    # / IP 部分：用 RandIP() 生成随机的源 IP 地址和目的 IP 地址，构建 IP 头部
    # / ICMP 部分：构建 ICMP（Internet 控制消息协议 ）头部，整体组成一个完整的网络数据包
    time.sleep(0.5)
    # 让程序暂停 0.5 秒，控制发包的频率，避免过快发包可能引发的问题或占用过多资源
    sendp(packet, iface=iface, loop=0)
    # 使用 sendp 函数发送构建好的数据包（sendp 用于在链路层发送数据包 ）
    # 参数 packet 是要发送的数据包；iface 指定发送数据包的网络接口；loop=0 表示不循环发送（这里外层已经是无限循环，所以这里设为 0  ）