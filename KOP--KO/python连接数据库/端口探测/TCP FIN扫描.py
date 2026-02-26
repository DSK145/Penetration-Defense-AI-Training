from scapy.all import IP, TCP, sr1
import platform
from socket import socket, AF_INET, SOCK_STREAM

print("FIN扫描适用于非Windows系统（Windows对FIN包响应与UNIX类不同）")
print("开放端口无响应，关闭端口返回RST")
print("需要管理员权限运行sudo")
def load_system_signatures(file_path):
    """加载文件中系统特征"""
    signatures = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f.readlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                port, service, sys_sig = line.split(':', 2)
                signatures[int(port)] = {'service': service, 'system': sys_sig}
        print(f"成功加载特征文件：{file_path}")
    except Exception as e:
        print(f"加载特征文件失败：{e}")
    return signatures

def scan_with_file_judge():
    sys = platform.system()
    print(f"系统：{sys} | 权限不足：Win用管理员，Linux/macOS加sudo")

    target_ip = input("目标IP（仅限授权环境）：")
    fake_ip = input("伪造源IP：")
    start_port = int(input("起始端口："))
    end_port = int(input("结束端口："))
    sig_file = input("系统特征文件路径（如D:/sig.txt）：")

    sys_signatures = load_system_signatures(sig_file)
    if not sys_signatures:
        print("无有效特征，无法进行系统判断")
        return

    print(f"\nFIN扫描 {target_ip}:{start_port}-{end_port}（伪造IP：{fake_ip}）")
    for port in range(start_port, end_port + 1):
        try:
            pkt = IP(src=fake_ip, dst=target_ip)/TCP(dport=port, flags="F")
            resp = sr1(pkt, timeout=0.5, verbose=0)
            # FIN扫描：无响应为开放，收到RST为关闭
            if resp is None:
                if port in sys_signatures:
                    service = sys_signatures[port]['service']
                    system = sys_signatures[port]['system']
                    print(f"端口 {port}：开放 | 服务：{service} | 推测系统：{system}")
                else:
                    print(f"端口 {port}：开放 | 服务：Unknown")
            elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:  # RST-ACK
                pass  # 端口关闭，不输出
        except Exception:
            continue

if __name__ == "__main__":
    scan_with_file_judge()