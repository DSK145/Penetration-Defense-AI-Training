from scapy.all import IP, TCP, sr1, ICMP
import time
import matplotlib.pyplot as plt
import random

def check_target_alive(target_ip, timeout=2):
    ping_packet = IP(dst=target_ip)/ICMP()
    ping_response = sr1(ping_packet, timeout=timeout, verbose=0)
    if ping_response:
        print(f" 目标 {target_ip} 存活，开始伪装IP扫描...")
        return True
    else:
        print(f"目标 {target_ip} 不可达，终止扫描")
        return False

def generate_fake_ip():
    ip_segments = [
        f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
        f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
    ]
    return random.choice(ip_segments)

def tcp_null_scan_single_port(target_ip, port, use_fake_ip=True, timeout=1):
    if use_fake_ip:
        fake_src_ip = generate_fake_ip()
        null_packet = IP(dst=target_ip, src=fake_src_ip)/TCP(dport=port, flags="")
        print(f"伪装IP {fake_src_ip} → 扫描目标 {target_ip}:{port}")
    else:
        null_packet = IP(dst=target_ip)/TCP(dport=port, flags="")
        print(f"真实IP → 扫描目标 {target_ip}:{port}")
    response = sr1(null_packet, timeout=timeout, verbose=0)
    if response and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x14:
            return "closed"
        else:
            return "filtered"
    else:
        return "open"

def batch_null_scan(target_ip, ports, scan_delay=0.1, use_fake_ip=True):
    scan_result = {"open": [], "closed": [], "filtered": []}
    total_ports = len(ports)
    for idx, port in enumerate(ports, 1):
        print(f"\n 正在扫描端口 {port}（{idx}/{total_ports}）")
        status = tcp_null_scan_single_port(target_ip, port, use_fake_ip)
        scan_result[status].append(port)
        time.sleep(scan_delay)
    return scan_result

def visualize_scan_result(scan_result, target_ip):
    status_counts = [len(scan_result["open"]), len(scan_result["closed"]), len(scan_result["filtered"])]
    status_labels = ["开放端口", "关闭端口", "过滤端口"]
    colors = ["#2E8B57", "#DC143C", "#FF8C00"]
    plt.figure(figsize=(8, 6))
    plt.pie(status_counts, labels=status_labels, colors=colors, autopct="%1.1f%%", startangle=90)
    plt.title(f"TCP NULL扫描结果（IP伪装模式）- 目标IP：{target_ip}")
    plt.axis("equal")
    plt.show()

def export_result_to_file(scan_result, target_ip, filename="tcp_null_scan_result.txt"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"TCP NULL扫描报告（IP伪装模式）\n")
        f.write(f"目标IP：{target_ip}\n")
        f.write(f"扫描时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n")
        f.write("="*50 + "\n")
        f.write(f"开放端口（共{len(scan_result['open'])}个）：{sorted(scan_result['open'])}\n")
        f.write(f"关闭端口（共{len(scan_result['closed'])}个）：{sorted(scan_result['closed'])[:10]}...（仅显示前10个）\n")
        f.write(f"过滤端口（共{len(scan_result['filtered'])}个）：{sorted(scan_result['filtered'])}\n")
    print(f"\n 扫描结果已导出到：{filename}")

def get_user_input():
    target_ip = input("请输入目标IP地址：")
    port_input = input("请输入要扫描的端口范围（如 1-100 或 22,80,443）：")
    if "-" in port_input:
        start_port, end_port = map(int, port_input.split("-"))
        ports = range(start_port, end_port + 1)
    else:
        ports = [int(p) for p in port_input.split(",")]
    try:
        scan_delay = float(input("请输入扫描间隔（秒，如 0.2）："))
    except ValueError:
        scan_delay = 0.1
        print("输入无效，使用默认扫描间隔 0.1 秒")
    fake_ip_choice = input("是否启用IP伪装（隐藏真实IP）？(y/n)：").lower()
    use_fake_ip = True if fake_ip_choice == "y" else False
    return target_ip, ports, scan_delay, use_fake_ip

if __name__ == "__main__":
    print("===== TCP NULL 扫描工具（支持IP伪装） =====")
    TARGET_IP, SCAN_PORTS, SCAN_DELAY, USE_FAKE_IP = get_user_input()
    if not check_target_alive(TARGET_IP):
        exit()
    start_time = time.time()
    result = batch_null_scan(TARGET_IP, SCAN_PORTS, SCAN_DELAY, USE_FAKE_IP)
    end_time = time.time()
    print("\n" + "="*50)
    print(f"扫描完成！耗时：{end_time - start_time:.2f}秒")
    print(f"开放端口：{sorted(result['open'])}")
    print(f"关闭端口：{len(result['closed'])}个（示例：{sorted(result['closed'])[:5]}...）")
    print(f"过滤端口：{sorted(result['filtered'])}")
    visualize_choice = input("\n是否生成扫描结果可视化图表？(y/n)：").lower()
    if visualize_choice == "y":
        visualize_scan_result(result, TARGET_IP)
    export_choice = input("是否导出扫描结果到文件？(y/n)：").lower()
    if export_choice == "y":
        export_result_to_file(result, TARGET_IP)