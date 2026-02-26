import os
import csv
import time
import threading
import logging
from ipaddress import ip_address, ip_network

# 配置日志系统
logging.basicConfig(  # 设置日志配置
    level=logging.INFO,                      # 日志级别
    format="%(asctime)s - %(levelname)s - %(message)s", # 日志格式
    handlers=[logging.StreamHandler()]# 输出到控制台
)
logger = logging.getLogger("TIManager")

class TIManager:
    #威胁情报管理系统：融合流量日志与拦截IP，实现多维度分析
    def __init__(self, config=None): # 初始化配置
        self.config = config or {  # 默认配置
            "firewall_log": os.path.join(os.path.dirname(__file__), "firewall_log.csv"),  # 流量日志文件
            "blocked_ips": os.path.join(os.path.dirname(__file__), "blocked_ips.txt"),  # 拦截IP列表
            "refresh_interval": 300,  # 5分钟刷新一次
            "status_interval": 60     # 1分钟终端刷新一次状态
        }
        self.firewall_ips = {}  # 流量日志IP出现次数统计
        self.blocked_ips = set() # 去重后的拦截IP列表
        self.load_all_sources()
        self.start_refresh_thread() # 启动定时刷新线程
        self.start_status_thread() # 启动定时状态显示线程

    def load_all_sources(self): #加载所有情报源
        #加载所有情报源：流量日志、拦截IP列表
        self.load_firewall_log()#加载流量日志
        self.load_blocked_ips()#加载拦截IP列表

    def load_firewall_log(self, path=None):#加载防火墙流量日志
        #加载防火墙流量日志并统计IP出现次数
        p = path or self.config["firewall_log"] #日志文件路径
        if not os.path.exists(p):
            logger.warning(f"流量日志文件不存在：{p}")#警告日志window
            self.firewall_ips = {} #初始化为空
            return #返回
        try: #加载日志文件
            self.firewall_ips = {}#初始化IP统计字典
            with open(p, "r", encoding="utf-8") as f: #打开日志文件
                # 假设日志为CSV格式，且第二列为源IP（可根据实际调整）
                reader = csv.reader(f)#读取CSV内容
                next(reader)  # 跳过表头
                for row in reader:#遍历每行
                    if len(row) >= 2:#确保有足够列
                        ip = row[1].strip()#获取源IP
                        if ip:
                            self.firewall_ips[ip] = self.firewall_ips.get(ip, 0) + 1#统计IP出现次数
        except Exception as e:
            logger.error(f"加载流量日志失败：{str(e)}") #错误日志

    def load_blocked_ips(self, path=None):#加载拦截IP列表
        """加载拦截IP列表并去重"""
        p = path or self.config["blocked_ips"]  #拦截IP文件路径
        if not os.path.exists(p):#文件不存在
            logger.warning(f"拦截IP文件不存在：{p}")#警告日志
            self.blocked_ips = set()#初始化为空集合
            return#返回
        try:#加载拦截IP文件
            self.blocked_ips = set()#初始化集合
            with open(p, "r", encoding="utf-8") as f:#打开文件
                for line in f:#遍历每行
                    ip = line.strip()#去除空白
                    if ip:
                        self.blocked_ips.add(ip)#添加到集合去重
            logger.info(f"成功加载拦截IP列表（去重后）：{p}，共{len(self.blocked_ips)}个IP")#成功日志
        except Exception as e:#异常处理
            logger.error(f"加载拦截IP列表失败：{str(e)}") #错误日志

    def get_top_traffic_ips(self, limit=5):  #KOP--KO/KOP--KO/DDOS/AIPOR/ioader.py获取流量中出现频率最高的IP
        """获取流量中出现频率最高的IP""" #返回出现频率最高的前N个IP
        if not self.firewall_ips:#没有流量数据
            return []#如果没有流量数据，返回空列表
        return sorted(self.firewall_ips.items(), key=lambda x: x[1], reverse=True)[:limit]#排序并返回前N个

    def get_blocked_traffic_ips(self): #KOP--KO/KOP--KO/DDOS/AIPOR/ioader.py获取同时出现在流量和拦截列表中的IP
        """获取同时出现在流量和拦截列表中的IP"""
        return [ip for ip in self.blocked_ips if ip in self.firewall_ips]#返回同时出现在流量和拦截列表中的IP列表

    def start_refresh_thread(self):#KOP--KO/KOP--KO/DDOS/AIPOR/ioader.py启动定时刷新线程
        """启动定时刷新所有情报源的线程"""#启动定时刷新所有情报源的线程
        def refresh_loop():#刷新循环
            while True:
                self.load_all_sources()#加载所有情报源
                time.sleep(self.config["refresh_interval"])#等待下次刷新
        refresh_thread = threading.Thread(target=refresh_loop, daemon=True)#创建守护线程
        refresh_thread.start()#启动线程
        logger.info(f"定时刷新线程启动，间隔{self.config['refresh_interval']}秒")#启动日志

    def start_status_thread(self): #KOP--KO/KOP--KO/DDOS/AIPOR/ioader.py启动定时状态显示线程
        """启动定时在终端显示状态的线程"""
        def status_loop():
            while True:
                self.print_status()
                time.sleep(self.config["status_interval"])
        status_thread = threading.Thread(target=status_loop, daemon=True)
        status_thread.start()
        logger.info(f"状态显示线程启动，间隔{self.config['status_interval']}秒")

    def print_status(self):
        """在终端打印系统综合状态"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print("=" * 60)
        print(f"      流量与拦截IP分析系统 - 状态 ({time.strftime('%Y-%m-%d %H:%M:%S')})")
        print("=" * 60)
        print(f"  NSA流量日志统计:")
        print(f"   KO - 日志文件: {self.config['firewall_log']}")
        print(f"    独立IP数: {len(self.firewall_ips)}")
        print(f"    高频IP前3: {', '.join([f'{ip}({cnt}次)' for ip, cnt in self.get_top_traffic_ips(3)])}")
        print("-" * 60)
        print(f"     拦截IP列表统计:")
        print(f"     拦截文件: {self.config['blocked_ips']}")
        print(f"     去重后IP数: {len(self.blocked_ips)}")
        print(f"     流量中出现的拦截IP数: {len(self.get_blocked_traffic_ips())}")
        print("=" * 60)

def run_ti_management(config=None):
    ti_manager = TIManager(config=config)
    logger.info("流量与拦截IP分析系统已启动，持续运行中...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("程序退出")

if __name__ == "__main__":    # 作为主程序运行kdandaj
    run_ti_management()