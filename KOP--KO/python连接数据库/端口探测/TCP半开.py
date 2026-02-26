from scapy.all import *
import random
import time
import socket
import platform
from scapy.all import TCP, fragment
def get_local_ip():
    """移除netifaces，用系统原生方法获取本地IP（双系统兼容）"""
    try:
        # 通用方案：通过UDP连接公共地址获取真实出口IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 80))  # 连接谷歌DNS（仅用于获取本地IP，不发送数据）
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except:
        # 备选方案：返回默认本地IP
        return "127.0.0.1"

def manual_config():
    print("TCP半开扫描（SYN扫描）- 防火墙突破/激进扫描 手动配置")
    
    while True:
        target_ip = input("\n1. 目标IP地址：").strip()
        try:
            socket.inet_aton(target_ip)
            break
        except:
            print("IP格式错误，请重新输入")

    port_input = input("2. 扫描端口（格式：80 或 1-100 或 80,443,22）：").strip()
    ports = []
    try:
        for part in port_input.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        ports = list(set(ports))
    except:
        print("端口格式错误，支持：80、1-100、80,443,22")
        exit(1)

    print("\n防火墙突破与激进扫描参数")
    strat_choice = input("3. 扫描策略（1=隐蔽扫描；2=激进突破；3=自定义）：").strip()
    if strat_choice not in ["1", "2", "3"]:
        print("策略选择错误，请输入1/2/3")
        exit(1)

    ttl = input("4. TTL值（默认64，可伪装路径）：").strip()
    ttl = int(ttl) if ttl else 64

    window = input("5. 窗口大小（默认5840，模拟正常流量）：").strip()
    window = int(window) if window else 5840

    delay = input("6. 发包间隔（秒，默认0.2，激进可设0.05）：").strip()
    delay = float(delay) if delay else 0.2

    frag_size = 0
    decoy_count = 0
    spoof_port = 0
    if strat_choice in ["2", "3"]:
        frag_size = input("7. IP分片大小（8的倍数，默认0=不分段）：").strip()
        frag_size = int(frag_size) if frag_size else 0

        decoy_count = input("8. 诱饵IP数量（默认0=无诱饵）：").strip()
        decoy_count = int(decoy_count) if decoy_count else 0

        spoof_port = input("9. 伪装源端口（如80/443，默认0=随机）：").strip()
        spoof_port = int(spoof_port) if spoof_port else 0

    return {
        "target_ip": target_ip,
        "ports": ports,
        "strat": strat_choice,
        "ttl": ttl,
        "window": window,
        "delay": delay,
        "frag_size": frag_size,
        "decoy_count": decoy_count,
        "spoof_port": spoof_port
    }

def tcp_syn_scan(config):
    target_ip = config["target_ip"]
    ports = config["ports"]
    ttl = config["ttl"]
    window = config["window"]
    delay = config["delay"]
    frag_size = config["frag_size"]
    decoy_count = config["decoy_count"]
    spoof_port = config["spoof_port"]

    local_ip = get_local_ip()
    print(f"开始TCP半开扫描（目标：{target_ip}，本地IP：{local_ip}）")
    print(f"配置：TTL={ttl}，窗口={window}，间隔={delay}秒")
    if config["strat"] in ["2", "3"]:
        print(f"激进突破：分片大小={frag_size}，诱饵IP数={decoy_count}，伪装端口={spoof_port}")
    print("-"*30)

    for port in ports:
        print(f"扫描端口 {port}...", end="\r")
        # 生成诱饵IP（干扰防火墙检测）
        decoys = []
        if decoy_count > 0:
            for _ in range(decoy_count):
                decoy_ip = f"192.168.1.{random.randint(2, 254)}"
                decoys.append(IP(dst=target_ip, src=decoy_ip, ttl=ttl))

        # 构造扫描包（SYN标志位，半开扫描核心）
        ip = IP(dst=target_ip, src=local_ip, ttl=ttl)
        sport = spoof_port if spoof_port != 0 else random.randint(1024, 65535)
        tcp = TCP(sport=sport, dport=port, flags="S", window=window)

        # 发送诱饵包
        for decoy in decoys:
            send(decoy/tcp, verbose=0)
            time.sleep(delay / (decoy_count + 1))

        # 发送真实扫描包（支持IP分片）
        if frag_size > 0 and frag_size % 8 == 0:
            send(fragment(ip/tcp, fragsize=frag_size), verbose=0)
        else:
            send(ip/tcp, verbose=0)

        # 解析响应（半开扫描：收到SYN-ACK即判定开放，不建立完整连接）
        response = sr1(ip/tcp, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            if response[TCP].flags == "SA":  # SYN-ACK：端口开放
                # 发送RST复位，避免目标残留半连接
                rst = TCP(sport=sport, dport=port, flags="R", seq=response[TCP].ack, ack=response[TCP].seq + 1)
                send(ip/rst, verbose=0)
                print(f"端口 {port} | 开放")
            elif response[TCP].flags == "R":  # RST：端口关闭
                print(f"端口 {port} | 关闭")
            else:
                print(f"端口 {port} | 未知响应")
        else:
            print(f"端口 {port} | 被过滤")
        time.sleep(delay)

    print("-"*30)
    print("扫描结束！")

if __name__ == "__main__":
    try:
        config = manual_config()
        tcp_syn_scan(config)
    except KeyboardInterrupt:
        print("\n用户终止扫描")
    except Exception as e:
        print(f"扫描异常：{str(e)}")