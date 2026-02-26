import socket
import sys
import struct
import random
from datetime import datetime
import platform

# -------------------------- 核心工具函数（双系统兼容）--------------------------
def calculate_checksum(data):
    """TCP校验和计算（规避防火墙数据包检测）"""
    checksum = 0
    data_len = len(data)
    if data_len % 2 != 0:
        data += b'\x00'
    for i in range(0, data_len, 2):
        checksum += struct.unpack('!H', data[i:i+2])[0]
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    return ~checksum & 0xffff

def get_local_ip():
    """自动获取本地IP（双系统兼容）"""
    try:
        # 优先通过UDP获取真实出口IP（避免127.0.0.1）
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except:
        return "0.0.0.0"

def send_xmas_packet(src_ip, dst_ip, dst_port, ttl=64, window_size=5840, os_type="linux"):
    """发送XMAS包（FIN+URG+PUSH），适配Windows/Linux套接字差异"""
    try:
        if os_type == "linux":
            # Linux：使用原始套接字，手动构造IP头
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        else:
            # Windows：原始套接字需管理员，依赖系统自动填充部分IP字段
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            # Windows不支持IP_HDRINCL（需驱动级操作，简化为仅构造TCP头）
    except PermissionError:
        print("\n❌ 权限不足！")
        print(f"  - Linux：需用 sudo python3 脚本名.py")
        print(f"  - Windows：需以「管理员身份」运行命令提示符/PowerShell")
        sys.exit(1)
    except socket.error as e:
        print(f"\n❌ 创建套接字失败：{e}")
        print(f"  - Windows提示：需开启「原始套接字访问权限」（管理员执行 netsh winsock set catalogname=Winsock2）")
        sys.exit(1)

    # 1. 构造TCP头部（核心：XMAS标志位 FIN(0x01)+URG(0x20)+PUSH(0x08) = 0x29）
    src_port = random.randint(1024, 65535)  # 随机源端口（规避防火墙检测）
    seq_num = random.randint(0, 0x7fffffff)
    ack_num = 0
    tcp_header = struct.pack(
        '!HHLLBBHHH',
        src_port,        # 源端口
        dst_port,        # 目标端口
        seq_num,         # 序列号
        ack_num,         # 确认号
        0x50,            # 数据偏移（20字节）+ 保留位
        0x29,            # XMAS标志位
        window_size,     # 窗口大小（模拟正常流量）
        0,               # TCP校验和（后续计算）
        0xffff           # 紧急指针（URG标志位必需）
    )

    # 2. 计算TCP校验和（需伪头部，双系统通用）
    pseudo_header = struct.pack(
        '!4s4sBBH',
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0x00,
        socket.IPPROTO_TCP,
        len(tcp_header)
    )
    tcp_checksum = calculate_checksum(pseudo_header + tcp_header)
    tcp_header = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]

    # 3. 发送数据包（Windows/Linux差异处理）
    try:
        if os_type == "linux":
            # Linux：手动构造IP头（增强防火墙穿透）
            ip_header = struct.pack(
                '!BBHHHBBH4s4s',
                0x45,  # IPv4 + 头部长度20字节
                0x00,  # TOS
                40 + 20,  # 总长度（IP头20 + TCP头20）
                random.randint(1000, 65535),  # 随机IP标识
                0x0000,  # 片偏移
                ttl,  # 动态TTL
                socket.IPPROTO_TCP,
                0,  # IP校验和（内核自动填充）
                socket.inet_aton(src_ip),
                socket.inet_aton(dst_ip)
            )
            sock.sendto(ip_header + tcp_header, (dst_ip, 0))
        else:
            # Windows：仅发送TCP头（系统自动补IP头）
            sock.sendto(tcp_header, (dst_ip, dst_port))
        sock.close()
        return True
    except socket.error as e:
        print(f"  端口{dst_port}发送失败：{e}")
        sock.close()
        return False

def detect_port_status(dst_ip, dst_port, timeout=2):
    """检测端口状态：无响应=开放/过滤，RST=关闭（双系统兼容）"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.settimeout(timeout)
        sock.bind(('', 0))
    except socket.error as e:
        print(f" 监听响应失败：{e}")
        return "未知"

    status = "开放/过滤"
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            # 解析IP头（过滤非目标IP响应）
            ip_header_len = (data[0] & 0x0f) * 4
            src_ip = socket.inet_ntoa(data[12:16])
            if src_ip != dst_ip:
                continue
            # 解析TCP头（检测RST标志位）
            tcp_header_start = ip_header_len
            src_port = struct.unpack('!H', data[tcp_header_start:tcp_header_start+2])[0]
            tcp_flags = struct.unpack('!B', data[tcp_header_start+13:tcp_header_start+14])[0]
            if src_port == dst_port and (tcp_flags & 0x04):  # RST=0x04
                status = "关闭"
                break
    except socket.timeout:
        pass  # 超时=开放/过滤
    except Exception as e:
        print(f"  解析响应异常：{e}")
    finally:
        sock.close()
    return status

# -------------------------- 手动配置函数（用户输入）--------------------------
def manual_config():
    """用户手动输入所有核心参数（精细化配置）"""
    print("="*60)
    print(" TCP XMAS扫描 - 手动精细化配置")
    print("="*60)

    # 1. 基础配置（必输）
    while True:
        dst_ip = input("\n1. 目标IP地址（如192.168.1.1）：").strip()
        try:
            socket.inet_aton(dst_ip)
            break
        except:
            print("IP格式错误！请重新输入（如192.168.1.1）")

    # 2. 端口配置（支持多种格式：单个/范围/逗号分隔）
    while True:
        port_input = input("2. 扫描端口（格式：80 或 1-100 或 80,443,22）：").strip()
        ports = []
        try:
            for part in port_input.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if start > end or start < 1 or end > 65535:
                        raise ValueError
                    ports.extend(range(start, end + 1))
                else:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.append(port)
            ports = list(set(ports))  # 去重
            if ports:
                break
            else:
                print("无有效端口！请输入1-65535范围内的端口")
        except:
            print("端口格式错误！支持：80、1-100、80,443,22")

    # 3. 系统选择（自动识别+手动修正）
    auto_os = "windows" if platform.system().lower() == "windows" else "linux"
    while True:
        os_choice = input(f"3. 运行系统（自动识别：{auto_os}，输入windows/linux确认）：").strip().lower()
        if os_choice in ["windows", "linux"]:
            break
        print("系统输入错误！仅支持windows或linux")

    # 4. 防火墙规避参数（手动调整，默认最优值）
    print("\n 防火墙规避参数（默认值经测试适配多数场景，可手动修改）")
    ttl = input("4. TTL值（建议32/64/128，默认64）：").strip()
    ttl = int(ttl) if ttl and 1 <= int(ttl) <= 255 else 64

    window_size = input("5. 窗口大小（建议5840/Linux、65535/Windows，默认5840）：").strip()
    window_size = int(window_size) if window_size and window_size.isdigit() else 5840

    timeout = input("6. 扫描超时时间（秒，默认2）：").strip()
    timeout = float(timeout) if timeout and float(timeout) > 0 else 2.0

    print("\n" + "="*60)
    return {
        "dst_ip": dst_ip,
        "ports": sorted(ports),
        "os_type": os_choice,
        "ttl": ttl,
        "window_size": window_size,
        "timeout": timeout
    }

# -------------------------- 主扫描函数（整合逻辑）--------------------------
def xmas_scan_manual():
    """主函数：手动配置+双系统扫描+防火墙规避"""
    # 1. 获取用户手动配置
    config = manual_config()
    dst_ip = config["dst_ip"]
    ports = config["ports"]
    os_type = config["os_type"]
    ttl = config["ttl"]
    window_size = config["window_size"]
    timeout = config["timeout"]

    # 2. 获取本地IP（源IP）
    local_ip = get_local_ip()
    print(f" 开始扫描（目标IP：{dst_ip}，系统：{os_type}，本地IP：{local_ip}）")
    print(f"扫描时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" 配置参数：TTL={ttl}，窗口大小={window_size}，超时={timeout}秒")
    print("-"*60)

    # 3. 逐端口扫描
    for idx, port in enumerate(ports, 1):
        print(f"[{idx}/{len(ports)}] 扫描端口 {port:5d}...", end="[{r")
        # 发送XMAS包（带防火墙规避参数）
        send_success = send_xmas_packet(local_ip, dst_ip, port, ttl, window_size, os_type)
        if not send_success:
            print(f"[{idx}/{len(ports)}] 端口 {port:5d} | 发送失败")
            continue
        # 检测端口状态
        status = detect_port_status(dst_ip, port, timeout)
        print(f"[{idx}/{len(ports)}] 端口 {port:5d} | {status:10s}")

    print("-"*60)
    print(" 扫描结束！")
    print("📌 结果说明：'开放/过滤' = 端口开放 或 被防火墙拦截（需交叉验证）")

# -------------------------- 启动程序 --------------------------
if __name__ == "__main__":
    try:
        xmas_scan_manual()
    except KeyboardInterrupt:
        print("\n\n 用户手动终止扫描！")
        sys.exit(0)