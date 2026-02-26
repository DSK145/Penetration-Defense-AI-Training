from scapy.all import *
import random
import time
import platform
import socket

def get_local_ip():
    if platform.system().lower() == "windows":
        return get_if_addr(conf.iface)
    else:
        import netifaces
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if iface.startswith('eth') or iface.startswith('wlan'):
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr']
        return "0.0.0.0"

def manual_config():
    print("TCP全开扫描 - 防火墙规避/突破 手动配置")
    
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

    print("\n防火墙规避参数")
    strat_choice = input("3. 规避策略（1=基础隐蔽；2=激进突破；3=自定义）：").strip()
    if strat_choice not in ["1", "2", "3"]:
        print("策略选择错误，请输入1/2/3")
        exit(1)

    ttl = input("4. TTL值（默认64）：").strip()
    ttl = int(ttl) if ttl else 64

    window = input("5. 窗口大小（默认5840）：").strip()
    window = int(window) if window else 5840

    delay = input("6. 发包间隔（秒，默认0.5）：").strip()
    delay = float(delay) if delay else 0.5

    frag_size = 0
    decoy_count = 0
    spoof_port = 0
    if strat_choice in ["2", "3"]:
        frag_size = input("7. IP分片大小（8的倍数，默认0）：").strip()
        frag_size = int(frag_size) if frag_size else 0

        decoy_count = input("8. 诱饵IP数量（默认0）：").strip()
        decoy_count = int(decoy_count) if decoy_count else 0

        spoof_port = input("9. 伪装源端口（默认0=随机）：").strip()
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

def tcp_full_open_scan(config):
    target_ip = config["target_ip"]
    ports = config["ports"]
    ttl = config["ttl"]
    window = config["window"]
    delay = config["delay"]
    frag_size = config["frag_size"]
    decoy_count = config["decoy_count"]
    spoof_port = config["spoof_port"]

    local_ip = get_local_ip()
    print(f"开始扫描（目标：{target_ip}，本地IP：{local_ip}）")
    print(f"配置：TTL={ttl}，窗口={window}，间隔={delay}秒")
    if "strat" in config and config["strat"] in ["2", "3"]:
        print(f"高级规避：分片大小={frag_size}，诱饵IP数={decoy_count}，伪装端口={spoof_port}")
    print("-"*30)

    for port in ports:
        print(f"扫描端口 {port}...", end="\r")
        decoys = []
        if decoy_count > 0:
            for _ in range(decoy_count):
                decoy_ip = f"192.168.1.{random.randint(2, 254)}"
                decoys.append(IP(dst=target_ip, src=decoy_ip, ttl=ttl))

        ip = IP(dst=target_ip, src=local_ip, ttl=ttl)
        sport = spoof_port if spoof_port != 0 else random.randint(1024, 65535)
        tcp = TCP(sport=sport, dport=port, flags="S", window=window)

        for decoy in decoys:
            send(decoy/tcp, verbose=0)
            time.sleep(delay / (decoy_count + 1))

        if frag_size > 0 and frag_size % 8 == 0:
            send(fragment(ip/tcp, fragsize=frag_size), verbose=0)
        else:
            send(ip/tcp, verbose=0)

        response = sr1(ip/tcp, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            if response[TCP].flags == "SA":
                ack = TCP(sport=sport, dport=port, flags="A", 
                         seq=response[TCP].ack, ack=response[TCP].seq + 1)
                send(ip/ack, verbose=0)
                print(f"端口 {port} | 开放")
            elif response[TCP].flags == "R":
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
        tcp_full_open_scan(config)
    except KeyboardInterrupt:
        print("\n用户终止扫描")
    except Exception as e:
        print(f"扫描异常：{str(e)}")