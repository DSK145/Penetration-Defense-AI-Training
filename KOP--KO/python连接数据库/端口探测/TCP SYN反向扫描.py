from scapy.all import IP, TCP, send, sniff
import time

target_ip = input("写入目标地址：").strip()
target_port = int(input("目标端口："))
local_ip = input("本机IP地址(如：192.168.0.1)：").strip()
ip_ID = []

def capture_id(pkt):
    if pkt.haslayer(IP) and pkt[IP].src == target_ip:
        ip_ID.append(pkt[IP].id)

# 发送 SYN 包
send(IP(dst=target_ip, src=local_ip)/TCP(dport=target_port, flags="S", sport=9999), verbose=0)
time.sleep(0.1)
# 发送 ACK 包
send(IP(dst=target_ip, src=local_ip)/TCP(dport=target_port, flags="A", sport=9999, seq=1), verbose=0)
# 抓包，监听目标IP返回的数据包
sniff(filter=f"ip src {target_ip}", prn=capture_id, timeout=1)

if len(ip_ID) >= 2 and ip_ID[1] > ip_ID[0]:
    print(f"[{target_ip}:{target_port}] 可能开放端口")
else:
    print(f"[{target_ip}:{target_port}] 可能关闭/不可达")