# 导入os模块：用于文件/文件夹操作（判断文件存在、拼接路径、遍历目录等）
import os  
# 导入platform模块：用于获取当前操作系统（区分Windows/Linux，适配不同系统命令）
import platform  
# 导入socket模块：用于建立网络连接、发送/接收数据（与目标IP+端口通信）
import socket
import time  


# -------------------------- 全局配置参数（移除固定文件名，保留通用配置） --------------------------
# 自动搜索文件的路径列表：程序优先在这些路径查找用户指定的任意文件
SEARCH_PATHS = [
    r"D:\DDOS\python连接数据库",  # Windows路径，加r避免反斜杠\被当作转义符
]
# 网络连接超时时间：超过10秒未连接成功则判定失败
TIMEOUT = 10
# 接收网络数据的缓冲区大小：一次最多接收4096字节（约4KB）
BUF_SIZE = 4096      

# -------------------------- 启动提示函数（更新提示，强调支持任意文件） --------------------------
def print_file_hints():
    """程序启动时打印指引，明确告知支持任意文件类型，同时提供历史参考路径"""
    print("=== 文件操作指引 ===")
    print("支持任意类型文件（如.txt、.csv、.json、.sql等）")
    print("无需局限于特定数据库文件，可选择任意需要发送内容的文件")
    print("-------------------------------------------------------------")
    # 保留历史参考路径，供用户参考文件存放位置
    print("【参考路径】过往常用文件位置：")
    print(r"Windows: D:\DDOS\SQL注入数据库\攻击数据库.sql（可放任意文件）")
    print(r"Linux: /root/DDOS/SQL注入数据库/攻击数据库.sql（可放任意文件）")
    print("预设搜索路径里面的python可执行文件需要另启动,格式为Python 文件名.py")
    print("-------------------------------------------------------------")
    print("其他功能1关联文件: 好玩的东西.py,SQL高级攻击.sql（非必要，仅作功能区分）")
    print("=============================================================\n")


# -------------------------- 查找任意文件函数（核心修改：完全支持任意文件） --------------------------
def find_any_file():
    """
    查找用户指定的任意类型文件，流程：
    1. 让用户输入想查找的文件名（支持任意后缀，如test.txt、data.csv）
    2. 先在配置的SEARCH_PATHS路径自动搜索
    3. 搜索无果则让用户手动输入完整路径，直到找到有效文件
    返回：找到的任意文件的完整路径（字符串）
    """
    try:
        # 第一步：让用户输入要操作的任意文件名（无预设，完全自主指定）
        target_filename = input("请输入要操作的文件名（支持任意类型，如xxx.txt/yyy.csv）: ").strip()
        # 避免用户输入空文件名
        while not target_filename:
            target_filename = input("文件名不能为空，请重新输入: ").strip()
        
        print(f"\n开始查找文件: {target_filename}")
        # 第二步：遍历配置路径自动搜索
        for base_path in SEARCH_PATHS:
            # 拼接“路径+文件名”，生成完整文件路径
            file_path = os.path.join(base_path, target_filename)  
            # 判断路径是否为有效文件（不是文件夹，且文件存在）
            if os.path.isfile(file_path):
                print(f"找到文件: {file_path}")
                return file_path
        
        # 第三步：自动搜索失败，进入手动输入路径模式
        print(f"未在预设路径找到 {target_filename}，请手动输入文件完整路径")
        while True:
            file_path = input("请输入任意文件的完整路径（如D:/test.csv）: ").strip()
            # 验证输入路径是否为有效文件
            if os.path.isfile(file_path):
                print(f"路径有效，确认文件: {file_path}")
                return file_path
            # 路径无效时提示重试（明确无效原因）
            print("路径无效（文件不存在/是文件夹/格式错误），请重新输入")
    
    except KeyboardInterrupt:
        # 捕获用户按Ctrl+C中断输入，友好退出
        print("\n已取消文件路径输入，程序退出")
        exit()  


# -------------------------- 检测IP连通性函数（注释强化逻辑） --------------------------
def ping_ip(ip):
    """
    检测目标IP是否可达，兼容Windows和Linux系统的ping命令差异
    参数：ip - 目标IP地址（字符串）
    返回：True（IP可达）/ False（IP不可达）
    """
    # 获取当前系统名称并转为小写（统一判断标准）
    system = platform.system().lower()
    # Windows用-n 1（发送1个数据包），Linux/macOS用-c 1（同功能）
    ping_param = "-n 1" if system == "windows" else "-c 1"  
    # 执行系统ping命令：返回0代表成功（可达），非0代表失败（不可达）
    return os.system(f"ping {ping_param} {ip}") == 0  


# -------------------------- 验证端口有效性函数（细节注释补充） --------------------------
def validate_port(port_input):
    """
    验证用户输入的端口是否合法（合法范围：1-65535的整数）
    参数：port_input - 用户输入的端口内容（字符串，可能是数字/字母/符号）
    返回：(是否合法, 处理后端口/原输入) - 元组，方便后续逻辑判断
    """
    try:
        # 尝试将输入转为整数（端口必须是整数）
        port = int(port_input)
        # 判定是否在合法端口范围内
        if 1 <= port <= 65535:
            return True, port
        else:
            return False, port_input
    except ValueError:
        # 输入无法转整数（如输入"abc"），判定为无效
        return False, port_input
    except KeyboardInterrupt:
        # 捕获用户中断输入，友好退出
        print("\n已取消端口输入，程序退出")
        exit()


# -------------------------- 发送数据函数（适配任意文件内容发送） --------------------------
def send_line(ip, port, content):
    """
    向目标IP+端口发送单行内容（模拟HTTP POST请求，兼容任意文件的文本内容）
    参数：
        ip - 目标IP地址（字符串）
        port - 目标端口（整数）
        content - 要发送的单行内容（来自任意文件的一行文本）
    返回：(发送是否成功, 响应内容/错误信息) - 元组，反馈发送结果
    """
    try:
        # 创建socket对象（TCP协议，默认参数），with语法自动关闭socket，避免资源泄漏
        with socket.socket() as s:
            # 设置socket超时时间，避免长期阻塞
            s.settimeout(TIMEOUT)
            # 建立与目标IP+端口的连接
            s.connect((ip, port))
            
            # 构造POST请求体：将单行内容封装为表单格式（通用格式，服务端易识别）
            post_data = f"content={content}"  
            # 构造完整HTTP请求头：符合HTTP协议规范，确保服务端能正确解析
            http_request = (
                f"POST / HTTP/1.1\r\n"          # 请求方法（POST）、路径（/）、协议版本（HTTP/1.1）
                f"Host: {ip}\r\n"               # 目标主机IP（告知服务端请求的主机）
                f"Content-Length: {len(post_data)}\r\n"  # 告知服务端请求体的长度
                "Content-Type: application/x-www-form-urlencoded\r\n"  # 请求体类型（表单）
                "Connection: close\r\n\r\n"     # 发送完数据后关闭连接
                f"{post_data}"                  # 拼接请求体（实际要发送的内容）
            )
            # 将字符串请求转为字节流（socket仅支持发送字节），并完整发送
            s.sendall(http_request.encode())
            
            # 接收服务端响应：循环接收直到无数据（处理大响应场景）
            response = b""  # 初始化字节变量存响应
            while (part := s.recv(BUF_SIZE)):  # 每次接收BUF_SIZE字节，直到part为空
                response += part
            
            # 响应转为字符串（errors='replace'处理乱码，避免程序报错）
            return True, response.decode(errors='replace')
    
    except KeyboardInterrupt:
        # 捕获用户中断发送操作
        return False, "数据发送被手动中断（Ctrl+C）"
    except Exception as e:
        # 捕获其他网络异常（如连接超时、被拒绝、目标不可达等）
        return False, f"发送失败：{str(e)}"


# -------------------------- 查看Python文件函数（功能说明注释） --------------------------
def list_python_files():
    """
    列出脚本所在目录、SEARCH_PATHS路径下的所有Python文件（.py后缀）
    作用：帮助用户快速了解当前环境中的可操作Python脚本，避免选错文件
    """
    try:
        print("\n=== 当前可操作的 Python 文件列表 ===")
        # 1. 处理脚本所在目录（优先用__file__获取脚本路径，无则用当前工作目录）
        script_dir = os.path.dirname(__file__) if __file__ else os.getcwd()
        print(f"[1] 脚本所在目录: {script_dir}")
        # 遍历目录，筛选出.py文件并打印
        for file in os.listdir(script_dir):
            file_path = os.path.join(script_dir, file)
            if os.path.isfile(file_path) and file.endswith('.py'):
                print(f"  - {file}")
        
        # 2. 处理预设的SEARCH_PATHS路径（查找任意文件的路径，同步显示其中的Python文件）
        for idx, path in enumerate(SEARCH_PATHS, 2):
            print(f"\n[{idx}] 预设搜索路径: {path}")
            # 遍历路径，筛选.py文件并打印（路径不存在时跳过，避免报错）
            if os.path.exists(path):
                for file in os.listdir(path):
                    file_path = os.path.join(path, file)
                    if os.path.isfile(file_path) and file.endswith('.py'):
                        print(f"  - {file}")
            else:
                print(f"  该路径不存在或无法访问")
        
        print("====================================\n")
    except KeyboardInterrupt:
        # 捕获用户中断查看操作，返回主菜单
        print("\n已取消Python文件列表查看，返回主菜单")


# -------------------------- 主函数（程序入口，流程适配任意文件） --------------------------
def main():
    try:
        # 第一步：打印启动指引，告知用户支持任意文件
        print_file_hints()

        # 第二步：功能选择循环（持续运行，直到用户选择退出）
        while True:
            # 打印功能菜单（明确标注“任意文件”）
            print("请选择操作:")
            print("  1. 选择 攻击数据库.sql 并发送内容（支持.txt/.csv/.sql等所有文本类型,可使用自己的SQL注入文件，只需要给出文件路径就行，当前是内置）")
            print("  2. 查看当前可操作的 Python 文件")
            print("  3. 退出程序")
            
            # 获取用户选择（去除前后空格，避免误操作）
            choice = input("输入选项 (1/2/3): ").strip()
            
            # 选项1：选择任意文件并发送内容
            if choice == "1":
                # 调用查找函数，获取用户指定的任意文件路径
                target_file_path = find_any_file()
                
                # 子流程1：检测目标IP连通性（必须找到可达IP才能继续）
                print("\n=== 检测目标IP连通性 ===")
                while True:
                    try:
                        target_ip = input("请输入目标IP地址: ").strip()
                        # 避免空IP输入
                        if not target_ip:
                            print("IP不能为空，请重新输入")
                            continue
                        print(f"正在 ping {target_ip}...")
                        if ping_ip(target_ip):
                            print(f"{target_ip} 可达，继续下一步")
                            break
                        else:
                            print(f"{target_ip} 不可达，请重新输入")
                    except KeyboardInterrupt:
                        print("\n已取消IP输入，程序退出")
                        exit()
                
                # 子流程2：验证目标端口合法性（必须输入合法端口才能继续）
                print("\n=== 验证目标端口 ===")
                while True:
                    target_port_input = input("请输入目标端口（1-65535）: ").strip()
                    is_port_valid, target_port = validate_port(target_port_input)
                    if is_port_valid:
                        print(f"端口 {target_port} 合法，继续下一步")
                        break
                    else:
                        print(f"端口 {target_port_input} 无效，请输入1-65535之间的整数")
                
                # 子流程3：读取任意文件内容（按行读取，过滤空行）
                print(f"\n=== 读取文件内容 ===")
                try:
                    # 以UTF-8编码打开文件（文本类型通用编码，若遇特殊编码可手动调整）
                    with open(target_file_path, 'r', encoding='utf-8') as f:
                        # 遍历文件每一行，去除前后空格，过滤空行（只保留有效内容）
                        file_lines = [line.strip() for line in f if line.strip()]
                except UnicodeDecodeError:
                    # 捕获编码错误（如文件是GBK编码），提示用户调整编码
                    print(f"读取文件失败：文件编码不是UTF-8，请用记事本打开文件→另存为→选择UTF-8编码后重试")
                    # 回到功能选择循环，不终止程序
                    continue
                
                # 子流程4：逐行发送文件内容并接收响应
                print(f"成功读取文件，共 {len(file_lines)} 行有效内容，开始发送...\n")
                for line_num, line_content in enumerate(file_lines, 1):
                    # 打印发送进度（只显示前50个字符，避免内容过长刷屏）
                    print(f"=== 发送第 {line_num}/{len(file_lines)} 行 ===")
                    print(f"发送内容（前50字符）: {line_content[:50]}...")
                    # 调用发送函数，获取结果
                    send_success, response = send_line(target_ip, target_port, line_content)
                    
                    # 打印响应结果（用分隔线区分，更清晰）
                    print("响应结果:")
                    print("-" * 60)
                    print(response if send_success else f"发送失败：{response}")
                    print("-" * 60 + "\n")

            # 选项2：查看可操作的Python文件
            elif choice == "2":
                list_python_files()
            
            # 选项3：退出程序
            elif choice == "3":
                print("正在退出程序，感谢使用！")
                break
            
            # 无效选项处理
            else:
                print(f"无效选项 '{choice}'，请输入 1/2/3 选择操作")
    
    except KeyboardInterrupt:
        # 捕获主流程中的Ctrl+C中断
        print("\n程序被手动中断（Ctrl+C），已退出")


# -------------------------- 程序启动入口 --------------------------
# 当脚本被直接运行时/执行主函数
if __name__ == "__main__":
    main()