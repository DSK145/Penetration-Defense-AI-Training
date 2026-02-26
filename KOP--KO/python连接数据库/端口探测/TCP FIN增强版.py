from scapy.all import IP, TCP, sr1, sniff, Raw, ICMP
import platform
import random
import time
import re
import hashlib
import math
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import ipaddress

# ===================== 1. 内置核心特征库（Por扩充版） =====================
# 1.1 内置系统特征库（覆盖桌面/服务器/网络设备/物联网/国产系统）
BUILT_IN_SYSTEM_FP = [
    # -------------------- 桌面操作系统 --------------------
    {"os": "Windows 11", "ttl_min": 128, "ttl_max": 128, "tcp_window": 65535, "df_flag": True, 
     "ports": [3389, 445, 5985, 5986], "desc": "微软最新桌面系统，开启RDP(3389)、SMB(445)、WinRM(5985/5986)"},
    {"os": "Windows 10", "ttl_min": 128, "ttl_max": 128, "tcp_window": 65535, "df_flag": True, 
     "ports": [3389, 445, 5985], "desc": "主流桌面系统，TTL=128，默认开启SMB，支持远程桌面"},
    {"os": "Windows 7", "ttl_min": 128, "ttl_max": 128, "tcp_window": 65535, "df_flag": True, 
     "ports": [3389, 445], "desc": "老旧桌面系统，无WinRM端口，SMB协议版本较旧"},
    {"os": "macOS Sonoma (14.x)", "ttl_min": 64, "ttl_max": 64, "tcp_window": 65535, "df_flag": True, 
     "ports": [22, 548, 631], "desc": "苹果桌面系统，TTL=64，AFP(548)文件共享、IPP打印(631)，SSH需手动开启"},
    {"os": "macOS Ventura (13.x)", "ttl_min": 64, "ttl_max": 64, "tcp_window": 65535, "df_flag": True, 
     "ports": [22, 548, 631], "desc": "苹果桌面系统，与Sonoma指纹一致，仅系统版本差异"},
    {"os": "Ubuntu Desktop 22.04", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443, 631], "desc": "主流Linux桌面，TTL=64，默认开启SSH、CUPS打印(631)"},
    {"os": "Linux Mint 21", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443], "desc": "基于Ubuntu的桌面系统，适合新手，默认SSH开启"},
    {"os": "Deepin 23", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443], "desc": "国产Linux桌面，内置WPS、微信等软件，默认SSH开启"},
    {"os": "Fedora Workstation 39", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443, 631], "desc": "Red Hat系桌面，支持最新开源软件，SSH默认开启"},
    {"os": "Chrome OS", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443], "desc": "谷歌云桌面系统，基于Linux，默认开启SSH，依赖云端应用"},

    # -------------------- 服务器操作系统 --------------------
    {"os": "Windows Server 2022", "ttl_min": 128, "ttl_max": 128, "tcp_window": 65535, "df_flag": True, 
     "ports": [135, 3389, 445, 5985, 5986], "desc": "微软企业服务器，开启RPC(135)、WinRM(5985/5986)"},
    {"os": "Windows Server 2019", "ttl_min": 128, "ttl_max": 128, "tcp_window": 65535, "df_flag": True, 
     "ports": [135, 3389, 445, 5985], "desc": "微软服务器，与2022差异仅版本，核心端口一致"},
    {"os": "Linux CentOS Stream 9", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443, 3306], "desc": "企业级Linux，常用于Web、MySQL(3306)服务器，稳定性高"},
    {"os": "Linux RHEL 9", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443, 5432], "desc": "Red Hat企业版，适合PostgreSQL(5432)等商业数据库"},
    {"os": "Linux Debian 12", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443, 27017], "desc": "稳定开源服务器，常用于MongoDB(27017)、Nginx服务"},
    {"os": "SUSE Linux Enterprise 15", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443, 1521], "desc": "企业级Linux，适配Oracle数据库(1521)，主打高可用"},
    {"os": "Oracle Linux 9", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443, 1521], "desc": "Oracle优化版Linux，默认适配Oracle数据库，性能优化"},
    {"os": "FreeBSD 14", "ttl_min": 64, "ttl_max": 64, "tcp_window": 65535, "df_flag": False, 
     "ports": [22, 80, 443], "desc": "类Unix服务器，DF标志默认关闭，适合高并发网络服务"},
    {"os": "Kylin Server V10", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443, 3306], "desc": "国产服务器系统，适配政务/国企场景，兼容主流数据库"},
    {"os": "UOS Server 20", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443, 5432], "desc": "国产服务器系统，基于Debian，支持国产化硬件"},

    # -------------------- 网络设备操作系统 --------------------
    {"os": "Cisco IOS (路由器)", "ttl_min": 255, "ttl_max": 255, "tcp_window": 4128, "df_flag": True, 
     "ports": [22, 23, 443], "desc": "思科路由器系统，TTL=255，开启SSH(22)、Telnet(23)、HTTPS管理(443)"},
    {"os": "Cisco IOS-XE (交换机)", "ttl_min": 255, "ttl_max": 255, "tcp_window": 4128, "df_flag": True, 
     "ports": [22, 23, 443], "desc": "思科交换机系统，TTL=255，与IOS指纹一致，设备类型差异"},
    {"os": "Huawei VRP (路由器/交换机)", "ttl_min": 255, "ttl_max": 255, "tcp_window": 4380, "df_flag": True, 
     "ports": [22, 23, 443], "desc": "华为设备系统，TTL=255，TCP窗口=4380，区别于思科"},
    {"os": "H3C Comware (交换机)", "ttl_min": 255, "ttl_max": 255, "tcp_window": 4380, "df_flag": True, 
     "ports": [22, 23, 443], "desc": "H3C交换机系统，TTL=255，与华为VRP指纹接近，端口一致"},
    {"os": "Juniper Junos (路由器)", "ttl_min": 255, "ttl_max": 255, "tcp_window": 4128, "df_flag": True, 
     "ports": [22, 443], "desc": "瞻博路由器系统，TTL=255，默认关闭Telnet，仅开SSH/HTTPS"},
    {"os": "TP-Link 嵌入式系统 (路由器)", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [80, 443], "desc": "家用TP-Link路由器，默认关闭SSH，仅开Web管理端口"},
    {"os": "OpenWRT (路由器)", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443], "desc": "开源路由器系统，默认开启SSH、Web管理，支持插件扩展"},

    # -------------------- 物联网/嵌入式系统 --------------------
    {"os": "Android 14 (手机)", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [5555], "desc": "安卓手机系统，TTL=64，ADB调试端口(5555)，无固定服务端口"},
    {"os": "Android 13 (手机)", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [5555], "desc": "安卓手机系统，与14指纹一致，版本差异"},
    {"os": "iOS 17 (iPhone)", "ttl_min": 64, "ttl_max": 64, "tcp_window": 65535, "df_flag": True, 
     "ports": [49152, 49153], "desc": "苹果手机系统，TTL=64，仅动态端口，默认关闭固定服务"},
    {"os": "iOS 16 (iPhone)", "ttl_min": 64, "ttl_max": 64, "tcp_window": 65535, "df_flag": True, 
     "ports": [49152, 49153], "desc": "苹果手机系统，与17指纹一致，版本差异"},
    {"os": "ESP32 嵌入式系统 (物联网)", "ttl_min": 64, "ttl_max": 64, "tcp_window": 1460, "df_flag": False, 
     "ports": [80, 8080], "desc": "ESP32物联网设备，TTL=64，TCP窗口=1460，DF标志关闭，常运行Web服务"},
    {"os": "Raspberry Pi OS (物联网)", "ttl_min": 64, "ttl_max": 64, "tcp_window": 5840, "df_flag": True, 
     "ports": [22, 80, 443], "desc": "树莓派系统，基于Debian，默认开启SSH，适合物联网项目"}
]

# 1.2 内置算法关键字特征库（覆盖哈希/对称/非对称/流密码/国密算法）
BUILT_IN_ALGO_KEYWORDS = [
    # -------------------- 哈希算法 --------------------
    {"name": "SHA-256", "keywords": ["SHA-256", "SHA256", "sha256=", "SHA_256"], "type": "hash"},
    {"name": "SHA-384", "keywords": ["SHA-384", "SHA384", "sha384=", "SHA_384"], "type": "hash"},
    {"name": "SHA-512", "keywords": ["SHA-512", "SHA512", "sha512=", "SHA_512"], "type": "hash"},
    {"name": "MD5", "keywords": ["MD5", "md5=", "MD5SUM", "md5sum"], "type": "hash"},
    {"name": "CRC32", "keywords": ["CRC32", "crc32=", "CRC-32"], "type": "hash"},
    {"name": "SM3", "keywords": ["SM3", "sm3=", "国密SM3"], "type": "hash"},  # 国密哈希

    # -------------------- 对称加密算法 --------------------
    {"name": "AES-128", "keywords": ["AES-128", "AES128", "128-AES"], "type": "symmetric", "block_size": 16},
    {"name": "AES-256", "keywords": ["AES-256", "AES256", "256-AES"], "type": "symmetric", "block_size": 16},
    {"name": "DES", "keywords": ["DES", "Data Encryption Standard"], "type": "symmetric", "block_size": 8},
    {"name": "3DES", "keywords": ["3DES", "Triple DES", "DES-EDE3"], "type": "symmetric", "block_size": 8},
    {"name": "Twofish", "keywords": ["Twofish", "TF-256", "Twofish-256"], "type": "symmetric", "block_size": 16},
    {"name": "Camellia", "keywords": ["Camellia", "Camellia-128", "Camellia-256"], "type": "symmetric", "block_size": 16},
    {"name": "SM4", "keywords": ["SM4", "sm4=", "国密SM4"], "type": "symmetric", "block_size": 16},  # 国密对称

    # -------------------- 非对称加密算法 --------------------
    {"name": "RSA-2048", "keywords": ["RSA-2048", "RSA2048", "2048-RSA"], "type": "asymmetric"},
    {"name": "RSA-4096", "keywords": ["RSA-4096", "RSA4096", "4096-RSA"], "type": "asymmetric"},
    {"name": "ECC-P256", "keywords": ["ECC-P256", "P-256", "secp256r1"], "type": "asymmetric"},
    {"name": "ECC-P384", "keywords": ["ECC-P384", "P-384", "secp384r1"], "type": "asymmetric"},
    {"name": "SM2", "keywords": ["SM2", "sm2=", "国密SM2"], "type": "asymmetric"},  # 国密非对称
        # -------------------- 非对称加密算法 --------------------
    {"name": "RSA-2048", "keywords": ["RSA-2048", "RSA2048", "2048-RSA"], "type": "asymmetric"},
    {"name": "RSA-4096", "keywords": ["RSA-4096", "RSA4096", "4096-RSA"], "type": "asymmetric"},
    {"name": "ECC-P256", "keywords": ["ECC-P256", "P-256", "secp256r1"], "type": "asymmetric"},
    {"name": "ECC-P384", "keywords": ["ECC-P384", "P-384", "secp384r1"], "type": "asymmetric"},
    {"name": "SM2", "keywords": ["SM2", "sm2=", "国密SM2"], "type": "asymmetric"},  # 国密非对称

    # -------------------- 流密码算法 --------------------
    {"name": "ChaCha20", "keywords": ["ChaCha20", "ChaCha", "chacha20="], "type": "stream"},
    {"name": "Salsa20", "keywords": ["Salsa20", "Salsa", "salsa20="], "type": "stream"},
    {"name": "RC4", "keywords": ["RC4", "ARC4", "rc4="], "type": "stream"},

    # -------------------- 组合/其他算法 --------------------
    {"name": "HMAC-SHA256", "keywords": ["HMAC-SHA256", "HMACSHA256"], "type": "combined", "base_algo": "SHA-256"},
    {"name": "TLS_AES_128_GCM_SHA256", "keywords": ["TLS_AES_128_GCM_SHA256", "TLS1.3_AES128"], "type": "combined", "protocol": "TLS1.3"},
    {"name": "PGP", "keywords": ["PGP", "Pretty Good Privacy"], "type": "combined", "desc": "混合加密（对称+非对称+哈希）"}
]

BUILT_IN_ALGO_RULES = {
    # 一、经典MD系列哈希算法
    "MD5": {
        "keywords": ["md5", "MD5", "md5sum", "Message-Digest 5", "RFC 1321", "MD5哈希"],
        "format": {"length": 32, "is_hex": True}  # 32位小写十六进制（标准输出）
    },
    "MD2": {
        "keywords": ["md2", "MD2", "MD2 Message-Digest", "RFC 1319", "MD2哈希"],
        "format": {"length": 32, "is_hex": True}  # 32位十六进制（与MD5长度一致，靠关键字区分）
    },
    "MD4": {
        "keywords": ["md4", "MD4", "MD4 Message-Digest", "RFC 1320", "MD4哈希"],
        "format": {"length": 32, "is_hex": True}  # 32位十六进制
    },

    # 二、SHA-1系列哈希算法
    "SHA-1": {
        "keywords": ["sha1", "SHA-1", "SHA1SUM", "SHA-1哈希", "RFC 3174", "Secure Hash Algorithm 1"],
        "format": {"length": 40, "is_hex": True}  # 40位十六进制
    },

    # 三、SHA-2系列哈希算法（主流安全算法）
    "SHA-224": {
        "keywords": ["sha224", "SHA-224", "SHA224SUM", "SHA-224哈希", "RFC 6234", "SHA-2 family"],
        "format": {"length": 56, "is_hex": True}  # 56位十六进制（224bit/4=56）
    },
    "SHA-256": {
        "keywords": ["sha256", "SHA-256", "SHA256SUM", "SHA-256哈希", "RFC 6234", "SHA-2核心算法"],
        "format": {"length": 64, "is_hex": True}  # 64位十六进制（256bit/4=64）
    },
    "SHA-384": {
        "keywords": ["sha384", "SHA-384", "SHA384SUM", "SHA-384哈希", "RFC 6234", "长字节哈希"],
        "format": {"length": 96, "is_hex": True}  # 96位十六进制（384bit/4=96）
    },
    "SHA-512": {
        "keywords": ["sha512", "SHA-512", "SHA512SUM", "SHA-512哈希", "RFC 6234", "高安全哈希"],
        "format": {"length": 128, "is_hex": True}  # 128位十六进制（512bit/4=128）
    },
    "SHA-512/224": {
        "keywords": ["sha512/224", "SHA-512/224", "SHA512-224", "SHA-512截断算法", "RFC 6234"],
        "format": {"length": 56, "is_hex": True}  # 56位十六进制（224bit/4=56）
    },
    "SHA-512/256": {
        "keywords": ["sha512/256", "SHA-512/256", "SHA512-256", "SHA-512短截断", "RFC 6234"],
        "format": {"length": 64, "is_hex": True}  # 64位十六进制（256bit/4=64）
    },

    # 四、SHA-3系列哈希算法（新一代标准）
    "SHA3-224": {
        "keywords": ["sha3-224", "SHA3-224", "SHA3-224哈希", "FIPS 202", "Keccak算法"],
        "format": {"length": 56, "is_hex": True}  # 56位十六进制
    },
    "SHA3-256": {
        "keywords": ["sha3-256", "SHA3-256", "SHA3-256哈希", "FIPS 202", "Keccak-256"],
        "format": {"length": 64, "is_hex": True}  # 64位十六进制
    },
    "SHA3-384": {
        "keywords": ["sha3-384", "SHA3-384", "SHA3-384哈希", "FIPS 202", "Keccak-384"],
        "format": {"length": 96, "is_hex": True}  # 96位十六进制
    },
    "SHA3-512": {
        "keywords": ["sha3-512", "SHA3-512", "SHA3-512哈希", "FIPS 202", "Keccak-512"],
        "format": {"length": 128, "is_hex": True}  # 128位十六进制
    },
    "SHA3-224/XOF": {
        "keywords": ["sha3-224xof", "SHA3-224XOF", "SHA3扩展输出", "FIPS 202", "XOF模式"],
        "format": {"length": 112, "is_hex": True}  # 扩展输出模式，默认224bit*2=448bit→112位十六进制
    },
    "SHA3-256/XOF": {
        "keywords": ["sha3-256xof", "SHA3-256XOF", "SHA3-256扩展", "FIPS 202", "Keccak-XOF"],
        "format": {"length": 128, "is_hex": True}  # 256bit*2=512bit→128位十六进制
    },

    # 五、国密算法（中国自主标准）
    "SM3": {
        "keywords": ["sm3", "SM3", "国密SM3", "GB/T 32905-2016", "SM3哈希", "国产密码算法"],
        "format": {"length": 64, "is_hex": True}  # 64位十六进制（256bit/4=64，与SHA-256长度一致）
    },

    # 六、CRC循环冗余校验算法（常用校验，非加密哈希）
    "CRC8": {
        "keywords": ["crc8", "CRC8", "CRC-8", "8位循环冗余校验", "CRC8-CCITT", "CRC8-SAE J1850"],
        "format": {"length": 2, "is_hex": True}  # 2位十六进制（8bit/4=2）
    },
    "CRC16": {
        "keywords": ["crc16", "CRC16", "CRC-16", "16位循环冗余校验", "CRC16-CCITT", "CRC16-Modbus"],
        "format": {"length": 4, "is_hex": True}  # 4位十六进制（16bit/4=4）
    },
    "CRC32": {
        "keywords": ["crc32", "CRC32", "CRC-32", "32位循环冗余校验", "CRC32-ISO", "CRC32-ZIP"],
        "format": {"length": 8, "is_hex": True}  # 8位十六进制（32bit/4=8，部分场景带0x前缀→10位，需代码兼容）
    },
    "CRC64": {
        "keywords": ["crc64", "CRC64", "CRC-64", "64位循环冗余校验", "CRC64-ECMA-182", "CRC64-ISO"],
        "format": {"length": 16, "is_hex": True}  # 16位十六进制（64bit/4=16）
    },

    # 七、小众/专用哈希算法
    "RIPEMD-128": {
        "keywords": ["ripemd128", "RIPEMD-128", "RIPEMD128", "RACE Integrity Primitives", "RFC 2286"],
        "format": {"length": 32, "is_hex": True}  # 32位十六进制（128bit/4=32）
    },
    "RIPEMD-160": {
        "keywords": ["ripemd160", "RIPEMD-160", "RIPEMD160", "比特币哈希组件", "RFC 2286"],
        "format": {"length": 40, "is_hex": True}  # 40位十六进制（160bit/4=40，与SHA-1长度一致）
    },
    "RIPEMD-256": {
        "keywords": ["ripemd256", "RIPEMD-256", "RIPEMD256", "256位RIPEMD", "RFC 2286"],
        "format": {"length": 64, "is_hex": True}  # 64位十六进制（256bit/4=64）
    },
    "RIPEMD-320": {
        "keywords": ["ripemd320", "RIPEMD-320", "RIPEMD320", "320位RIPEMD", "RFC 2286"],
        "format": {"length": 80, "is_hex": True}  # 80位十六进制（320bit/4=80）
    },
    "Whirlpool": {
        "keywords": ["whirlpool", "Whirlpool", "Whirlpool哈希", "ISO/IEC 10118-3", "512位哈希"],
        "format": {"length": 128, "is_hex": True}  # 128位十六进制（512bit/4=128，与SHA-512长度一致）
    },
    "Tiger": {
        "keywords": ["tiger", "Tiger", "Tiger哈希", "Tiger-192", "Tiger/192,3", "64位分组哈希"],
        "format": {"length": 48, "is_hex": True}  # 48位十六进制（192bit/4=48，Tiger-192标准输出）
    },
    "Snefru": {
        "keywords": ["snefru", "Snefru", "Snefru哈希", "NIST候选算法", "Snefru-128", "Snefru-256"],
        "format": {"length": 64, "is_hex": True}  # 64位十六进制（Snefru-256标准输出，256bit/4=64）
    },
    "GOST": {
        "keywords": ["gost", "GOST", "GOST哈希", "GOST R 34.11-94", "俄罗斯标准哈希", "GOST-3411"],
        "format": {"length": 64, "is_hex": True}  # 64位十六进制（256bit/4=64，与SHA-256/SM3长度一致）
    },

    # 八、物联网/嵌入式常用轻量哈希
    "BLAKE2b": {
        "keywords": ["blake2b", "BLAKE2b", "BLAKE2b-512", "轻量安全哈希", "RFC 7693", "BLAKE2系列"],
        "format": {"length": 128, "is_hex": True}  # 128位十六进制（BLAKE2b-512标准输出）
    },
    "BLAKE2s": {
        "keywords": ["blake2s", "BLAKE2s", "BLAKE2s-256", "嵌入式哈希", "RFC 7693", "轻量级BLAKE2"],
        "format": {"length": 64, "is_hex": True}  # 64位十六进制（BLAKE2s-256标准输出）
    },
    "Phash": {
        "keywords": ["phash", "PHash", "感知哈希", "图像哈希", "pHash-64", "图像相似度校验"],
        "format": {"length": 16, "is_hex": True}  # 16位十六进制（64bit感知哈希，常用于图像去重）
    },
    "Adler-32": {
        "keywords": ["adler32", "Adler-32", "Adler32", " Adler校验", "zlib校验算法", "轻量校验"],
        "format": {"length": 8, "is_hex": True}  # 8位十六进制（32bit校验值，与CRC32长度一致，靠关键字区分）
    }
}
# ===================== 2. 文件解析工具（支持用户自定义文件导入） =====================
# 2.1 解析用户系统特征文件（格式：系统名:TTL_min:TTL_max:TCP_window:DF_flag:端口(逗号):描述）
def load_user_system_file(file_path):
    user_sys = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f.readlines(), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':', 6)
                if len(parts) != 7:
                    print(f"[警告] 系统文件第{line_num}行格式错误（需7字段），跳过")
                    continue
                # 字段解析与校验
                try:
                    os_name = parts[0].strip()
                    ttl_min = int(parts[1].strip())
                    ttl_max = int(parts[2].strip())
                    tcp_window = int(parts[3].strip())
                    df_flag = parts[4].strip().lower() == 'true'
                    ports = [int(p.strip()) for p in parts[5].strip().split(',') if p.strip().isdigit()]
                    desc = parts[6].strip()
                except ValueError:
                    print(f"[警告] 系统文件第{line_num}行数值错误，跳过")
                    continue
                if ttl_min > ttl_max or tcp_window < 0 or any(p < 1 or p > 65535 for p in ports):
                    print(f"[警告] 系统文件第{line_num}行值无效，跳过")
                    continue
                user_sys.append({"os": os_name, "ttl_min": ttl_min, "ttl_max": ttl_max, "tcp_window": tcp_window, "df_flag": df_flag, "ports": ports, "desc": desc})
        print(f"[成功] 加载用户系统文件：{file_path}，共{len(user_sys)}条有效特征")
    except Exception as e:
        print(f"[错误] 加载系统文件失败：{str(e)}")
    return user_sys

# 2.2 解析用户算法关键字文件（格式：算法名:关键字(逗号):类型:额外参数(如block_size=16)）
def load_user_algo_keywords(file_path):
    user_algos = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f.readlines(), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':', 3)
                if len(parts) < 3:
                    print(f"[警告] 算法关键字文件第{line_num}行格式错误（需至少3字段），跳过")
                    continue
                # 基础字段解析
                algo_name = parts[0].strip()
                keywords = [kw.strip() for kw in parts[1].strip().split(',') if kw.strip()]
                algo_type = parts[2].strip().lower()
                if algo_type not in ['hash', 'symmetric', 'asymmetric', 'stream', 'combined']:
                    print(f"[警告] 算法关键字文件第{line_num}行类型错误（需hash/symmetric等），跳过")
                    continue
                # 解析额外参数（如block_size、base_algo）
                extra_params = {}
                if len(parts) == 4 and parts[3].strip():
                    for param in parts[3].strip().split(','):
                        if '=' in param:
                            key, val = param.strip().split('=', 1)
                            if key == 'block_size':
                                extra_params[key] = int(val.strip()) if val.strip().isdigit() else 0
                            elif key in ['base_algo', 'protocol', 'desc']:
                                extra_params[key] = val.strip()
                # 组装算法特征
                algo_info = {"name": algo_name, "keywords": keywords, "type": algo_type}
                algo_info.update(extra_params)
                user_algos.append(algo_info)
        print(f"[成功] 加载用户算法关键字文件：{file_path}，共{len(user_algos)}条有效算法")
    except Exception as e:
        print(f"[错误] 加载算法关键字文件失败：{str(e)}")
    return user_algos

# 2.3 解析用户算法样本文件（格式：算法名:输入值:输出值:额外参数(如key=xxx,iv=xxx)）
def load_user_algo_samples(file_path):
    user_samples = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f.readlines(), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':', 3)
                if len(parts) < 3:
                    print(f"[警告] 算法样本文件第{line_num}行格式错误（需至少3字段），跳过")
                    continue
                # 基础字段解析
                algo_name = parts[0].strip()
                input_val = parts[1].strip()
                output_val = parts[2].strip()
                if not algo_name or not input_val or not output_val:
                    print(f"[警告] 算法样本文件第{line_num}行字段为空，跳过")
                    continue
                # 解析额外参数（如key、iv、desc）
                extra_params = {}
                if len(parts) == 4 and parts[3].strip():
                    for param in parts[3].strip().split(','):
                        if '=' in param:
                            key, val = param.strip().split('=', 1)
                            extra_params[key] = val.strip()
                # 组装样本
                user_samples[algo_name] = {"input": input_val, "output": output_val}
                user_samples[algo_name].update(extra_params)
        print(f"[成功] 加载用户算法样本文件：{file_path}，共{len(user_samples)}条有效样本")
    except Exception as e:
        print(f"[错误] 加载算法样本文件失败：{str(e)}")
    return user_samples

# 2.4 合并内置与用户特征（重名覆盖，新名新增）
def merge_features(built_in, user):
    if isinstance(built_in, list):  # 系统特征、算法关键字（列表类型）
        merged_dict = {item["name"]: item for item in built_in} if "name" in built_in[0] else {item["os"]: item for item in built_in}
        for item in user:
            key = item["name"] if "name" in item else item["os"]
            merged_dict[key] = item
        return list(merged_dict.values())
    elif isinstance(built_in, dict):  # 算法样本（字典类型）
        merged_dict = built_in.copy()
        merged_dict.update(user)
        return merged_dict
    return built_in

# ===================== 3. 核心功能函数（基于合并后的特征库工作） =====================
# 3.1 提取数据包信息
def extract_packet_content(pkt):
    pkt_info = {
        "ip_src": pkt[IP].src if pkt.haslayer(IP) else None,
        "ip_dst": pkt[IP].dst if pkt.haslayer(IP) else None,
        "tcp_sport": pkt[TCP].sport if pkt.haslayer(TCP) else None,
        "tcp_dport": pkt[TCP].dport if pkt.haslayer(TCP) else None,
        "tcp_window": pkt[TCP].window if pkt.haslayer(TCP) else None,
        "tcp_df": pkt[IP].flags.DF if (pkt.haslayer(IP) and hasattr(pkt[IP].flags, "DF")) else None,
        "ttl": pkt[IP].ttl if pkt.haslayer(IP) else None,
        "payload": ""
    }
    if pkt.haslayer(Raw):
        try:
            pkt_info["payload"] = pkt[Raw].load.decode(errors="ignore") or pkt[Raw].load.hex()
        except:
            pkt_info["payload"] = pkt[Raw].load.hex()
    return pkt_info

# 3.2 基于数据包指纹探测系统类型（接收合并后的系统特征库）
def detect_system_by_fingerprint(pkt_info, final_system_features):
    if not all([pkt_info["ttl"], pkt_info["tcp_window"], pkt_info["tcp_df"] is not None]):
        return ["无法识别（指纹信息不全）"]
    
    matched_os = []
    for os_fp in final_system_features:
        ttl_match = os_fp["ttl_min"] <= pkt_info["ttl"] <= os_fp["ttl_max"]
        window_match = abs(pkt_info["tcp_window"] - os_fp["tcp_window"]) / os_fp["tcp_window"] <= 0.1
        df_match = pkt_info["tcp_df"] == os_fp["df_flag"]
        port_match = True
        if pkt_info["tcp_dport"] and os_fp["ports"]:
            port_match = pkt_info["tcp_dport"] in os_fp["ports"]
        match_count = sum([ttl_match, window_match, df_match, port_match])
        if match_count >= 3:
            matched_os.append((os_fp["os"], match_count))
    # 按匹配项数量降序排序
    matched_os.sort(key=lambda x: x[1], reverse=True)
    return [os for os, cnt in matched_os] if matched_os else ["未知系统"]

# 3.3 服务器算力扫描（基于哈希计算响应时间）
def scan_server_performance(target_ip, test_port=80, test_times=3):
    print(f"\n[+] 开始服务器算力扫描（目标：{target_ip}，测试{test_times}次）...")
    performance_stats = []
    test_data = "server_performance_test_" + str(random.randint(1000, 9999))
    expected_hash = hashlib.sha256(test_data.encode()).hexdigest()
    
    for i in range(test_times):
        try:
            sport = random.randint(1024, 65535)
            task_payload = f"calc_sha256:{test_data}"
            pkt = IP(dst=target_ip, ttl=random.randint(64, 128)) / TCP(sport=sport, dport=test_port, flags="S") / Raw(load=task_payload)
            
            start_time = time.time()
            resp = sr1(pkt, timeout=2, verbose=0)
            end_time = time.time()
            rtt = (end_time - start_time) * 1000  # 转毫秒
            
            if resp and resp.haslayer(Raw):
                resp_payload = resp[Raw].load.decode(errors="ignore")
                if expected_hash in resp_payload:
                    performance_stats.append({"rtt": rtt, "result": "valid"})
                    print(f"[*] 第{i+1}次测试：RTT={rtt:.2f}ms（结果正确）")
                else:
                    performance_stats.append({"rtt": rtt, "result": "invalid"})
                    print(f"[*] 第{i+1}次测试：RTT={rtt:.2f}ms（结果错误）")
            else:
                performance_stats.append({"rtt": None, "result": "no_response"})
                print(f"[*] 第{i+1}次测试：无响应")
            
            time.sleep(1)
        except Exception as e:
            performance_stats.append({"rtt": None, "result": "error"})
            print(f"[!] 第{i+1}次测试出错：{e}")
    
    valid_rtts = [s["rtt"] for s in performance_stats if s["rtt"] and s["result"] == "valid"]
    if not valid_rtts:
        return {"status": "failed", "msg": "无有效测试结果", "stats": performance_stats}
    
    avg_rtt = sum(valid_rtts) / len(valid_rtts)
    performance_score = max(3, min(10, 10 - (avg_rtt - 100) / 40))
    
    return {
        "status": "success",
        "avg_rtt": avg_rtt,
        "performance_score": round(performance_score, 1),
        "stats": performance_stats,
        "desc": f"算力评分{round(performance_score,1)}分（RTT越短评分越高）"
    }

# 3.4 检测数据包中的算法特征（接收合并后的算法关键字、样本库）
def detect_algo_in_packet(pkt_info, final_algo_keywords, final_algo_samples):
    detected_algos = []
    detected_hashes = []  # 新增：用于收集真实哈希
    payload = pkt_info["payload"].lower()
    for algo in final_algo_keywords:
        if any(kw.lower() in payload for kw in algo["keywords"]):
            algo_info = {"name": algo["name"], "type": algo["type"], "match_type": "keyword"}
            if algo["type"] == "hash":
                # 用样本库的长度和格式做正则匹配，提取所有疑似哈希
                hash_len = None
                if algo["name"] in final_algo_samples:
                    hash_len = len(final_algo_samples[algo["name"]]["output"])
                elif "length" in algo:
                    hash_len = algo["length"]
                if hash_len:
                    matches = re.findall(rf"[0-9a-f]{{{hash_len}}}", payload)
                    for h in matches:
                        detected_hashes.append({"algo": algo["name"], "hash": h})
                algo_info["verify_result"] = "passed" if detected_hashes else "failed"
            elif algo["type"] in ["symmetric", "asymmetric"] and "block_size" in algo:
                if all(c in "0123456789abcdef" for c in payload):
                    cipher_len = len(payload) // 2
                    algo_info["verify_result"] = "passed" if cipher_len % algo["block_size"] == 0 else "failed"
            else:
                algo_info["verify_result"] = "pending"
            detected_algos.append(algo_info)
    return detected_algos, detected_hashes

# ===================== 4. 主逻辑（整合系统探测+算力扫描+算法检测+哈希发送+系统特征获取） =====================
def integrated_network_detection():
    sys_type = platform.system()
    print("===== 整合型网络检测工具（仅授权环境使用） =====")
    print(f"当前系统: {sys_type}")
    if sys_type in ["Linux", "Darwin"]:
        print("提示: 需确保已用sudo运行, 否则无数据包抓取/发送权限")
    else:
        print("提示: Windows系统需以管理员身份运行, 否则功能可能受限")
        print("注意: Windows下Scapy抓包/发包兼容性较差，推荐在Linux环境运行以获得最佳效果。")
        print("如遇抓包失败、无响应、依赖报错等，请优先尝试Linux。")

    # 用户输入部分
    try:
        target_ip = input("目标IP（仅限授权环境）：").strip()
        if not target_ip:
            raise ValueError("目标IP不能为空")
        start_port = int(input("起始端口："))
        end_port = int(input("结束端口："))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError("端口范围不合法")
        # 新增：虚假IP输入
        fake_ip = input("如需伪造源IP进行SYN扫描，请输入IP（什么都不输入直接回车为随机内网IP）：").strip()
        try:
            if fake_ip:
                ipaddress.ip_address(fake_ip)  # 校验IP格式
        except Exception:
            print("输入的伪造IP格式无效，将自动使用随机内网IP")
            fake_ip = None
        # 新增：抓包时长输入
        capture_time_input = input("抓包持续时间（秒，什么都不输入直接回车默认10）：").strip()
        capture_time = int(capture_time_input) if capture_time_input.isdigit() and int(capture_time_input) > 0 else 10
        # 算力扫描选项
        do_perf_scan = input("是否进行服务器算力扫描？(y/n，什么都不输入直接回车为n)：").strip().lower()
        do_perf_scan = do_perf_scan if do_perf_scan in ["y", "n"] else "n"
    except Exception as e:
        print(f"输入参数错误：{e}")
        exit(1)

    # ---------- 新增：SYN扫描（带虚假IP） ----------
    syn_scan_with_fake_ip(target_ip, start_port, end_port, fake_ip=fake_ip)

    # ---------- 系统特征库选择 ----------
    print("\n【系统特征库选择】")
    user_sys_path = input("如需手动指定系统特征文件，请输入路径（什么都不输入直接回车使用内置）：").strip()
    final_system_fp = BUILT_IN_SYSTEM_FP.copy()
    if user_sys_path:
        user_sys = load_user_system_file(user_sys_path)
        if user_sys:
            final_system_fp = merge_features(BUILT_IN_SYSTEM_FP, user_sys)
            print("已加载自定义系统特征库")
        else:
            print("自定义文件加载失败，自动使用内置系统特征库")
    else:
        print("已选择使用内置系统特征库")

    # ---------- 算法关键字库选择 ----------
    print("\n【算法关键字库选择】")
    user_algo_keyword_path = input("如需手动指定算法关键字文件，请输入路径（什么都不输入直接回车使用内置）：").strip()
    final_algo_keywords = BUILT_IN_ALGO_KEYWORDS.copy()
    if user_algo_keyword_path:
        user_algos = load_user_algo_keywords(user_algo_keyword_path)
        if user_algos:
            final_algo_keywords = merge_features(BUILT_IN_ALGO_KEYWORDS, user_algos)
            print("已加载自定义算法关键字库")
        else:
            print("自定义文件加载失败，自动使用内置算法关键字库")
    else:
        print("已选择使用内置算法关键字库")

    # ---------- 算法样本库选择 ----------
    print("\n【算法样本库选择】")
    user_algo_sample_path = input("如需手动指定算法样本文件，请输入路径（什么都不输入直接回车使用内置）：").strip()
    final_algo_samples = BUILT_IN_ALGO_SAMPLES.copy() if 'BUILT_IN_ALGO_SAMPLES' in globals() else {}
    if user_algo_sample_path:
        user_samples = load_user_algo_samples(user_algo_sample_path)
        if user_samples:
            final_algo_samples = merge_features(BUILT_IN_ALGO_SAMPLES, user_samples) if 'BUILT_IN_ALGO_SAMPLES' in globals() else user_samples
            print("已加载自定义算法样本库")
        else:
            print("自定义文件加载失败，自动使用内置算法样本库")
    else:
        print("已选择使用内置算法样本库")

    # ---------- 步骤1：数据包抓取与分析（含哈希提取） ----------
    print(f"\n[+] 步骤1/4：抓取{target_ip}的数据包（持续{capture_time}秒）...")
    try:
        filter_rule = f"host {target_ip} and (tcp or udp)"
        packets = sniff(filter=filter_rule, timeout=capture_time)  # 去掉 verbose=0
        print(f"[+] 共抓取{len(packets)}个数据包，开始分析...")
    except Exception as e:
        print(f"[!] 数据包抓取失败：{e}")
        return

    system_detections = []
    algo_detections = []
    all_detected_hashes = []  # 新增：存储所有检测到的哈希值

    for pkt in packets:
        pkt_info = extract_packet_content(pkt)
        if pkt_info["ip_src"] == target_ip:
            # 系统类型探测
            os_result = detect_system_by_fingerprint(pkt_info, final_system_fp)
            system_detections.append(os_result)
            # 算法特征检测（含哈希提取）
            algos, hashes = detect_algo_in_packet(pkt_info, final_algo_keywords, final_algo_samples)
            if algos:
                algo_detections.extend(algos)
            if hashes:
                for h in hashes:
                    all_detected_hashes.append(f"{h['algo']}:{h['hash']}")

    # 步骤1结果打印
    print("\n[+] 步骤1结果：系统探测+算法检测+哈希提取")
    if system_detections:
        # 展示所有可能的系统及出现次数
        flat_os = [os for sublist in system_detections for os in (sublist if isinstance(sublist, list) else [sublist])]
        os_count = {}
        for os in flat_os:
            os_count[os] = os_count.get(os, 0) + 1
        sorted_os = sorted(os_count.items(), key=lambda x: x[1], reverse=True)
        print(f"   - 推测目标系统（按匹配次数降序）：")
        for os, count in sorted_os:
            print(f"     * {os}（出现{count}次）")
    else:
        print("   - 系统探测：无足够数据包指纹，无法识别")
    if algo_detections:
        algo_stats = {}
        for algo in algo_detections:
            name = algo["name"]
            algo_stats[name] = algo_stats.get(name, {"passed":0, "failed":0, "pending":0})
            algo_stats[name][algo["verify_result"]] += 1
        print("   - 检测到的算法：")
        for name, stats in algo_stats.items():
            print(f"     * {name}：通过{stats['passed']}次 | 失败{stats['failed']}次 | 待验证{stats['pending']}次")
    else:
        print("   - 算法检测：未发现任何算法特征")
    if all_detected_hashes:
        print(f"   - 共提取到 {len(all_detected_hashes)} 个有效哈希值")
    else:
        print("   - 未提取到有效哈希值，跳过哈希发送与系统特征获取")

    # ---------- 步骤2：随机选5个哈希，发送数据包并尝试获取系统特征 ----------
    if all_detected_hashes:
        print("\n[+] 步骤2/4：随机选择5个哈希，发送数据包并尝试获取系统特征")
        # 随机选5个哈希（若不足5个则取全部）
        selected_hashes = random.sample(all_detected_hashes, min(5, len(all_detected_hashes)))
        send_port = int(input("   - 请输入发送数据包的目标端口（如80）：").strip() or 80)

        successful_send_count = 0
        for idx, hash_data in enumerate(selected_hashes, 1):
            # 构造数据包：载荷为哈希值，目标端口为用户输入
            sport = random.randint(1024, 65535)
            pkt = IP(dst=target_ip, ttl=64) / TCP(sport=sport, dport=send_port, flags="S") / Raw(load=hash_data)
            print(f"   - 发送第 {idx} 个数据包（载荷：{hash_data}）...")
            try:
                resp = sr1(pkt, timeout=2, verbose=0)
                if resp:
                    print(f"     ✅ 数据包发送成功，收到响应！")
                    successful_send_count += 1
                    # 收到响应后，额外抓取一次数据包，尝试再次获取系统特征
                    resp_pkt_info = extract_packet_content(resp)
                    new_os_result = detect_system_by_fingerprint(resp_pkt_info, final_system_fp)
                    print(f"     → 从响应中探测到系统：{new_os_result}")
                else:
                    print(f"     ❌ 数据包发送后未收到响应")
            except Exception as e:
                print(f"     ❌ 发送数据包失败：{str(e)}")

        print(f"   - 共发送 {len(selected_hashes)} 个数据包，{successful_send_count} 个发送成功且收到响应")
    else:
        print("\n[+] 步骤2/4：无有效哈希，跳过此步骤")

    # ---------- 步骤3：服务器算力扫描（可选） ----------
    if do_perf_scan == "y":
        print(f"\n[+] 步骤3/4：服务器算力扫描（目标：{target_ip}）")
        perf_result = scan_server_performance(target_ip)
        if perf_result["status"] == "success":
            print(f"   - 平均RTT：{perf_result['avg_rtt']:.2f}ms")
            print(f"   - 算力评分：{perf_result['performance_score']}分")
            print(f"   - 结论：{perf_result['desc']}")
        else:
            print(f"   - 算力扫描失败：{perf_result['msg']}")
    else:
        print("\n[+] 步骤3/4：已跳过服务器算力扫描")

    print("\n[+] 步骤4/4：检测流程全部完成，请注意核查以上结果")

def syn_scan_with_fake_ip(target_ip, start_port, end_port, fake_ip=None, timeout=1):
    print(f"\n[+] [SYN扫描] 正在扫描 {target_ip} 端口 {start_port}-{end_port}（伪造源IP：{fake_ip or '无'}） ...")
    open_ports = []
    total_ports = end_port - start_port + 1
    for idx, port in enumerate(range(start_port, end_port + 1), 1):
        sport = random.randint(1024, 65535)
        src_ip = fake_ip if fake_ip else f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=port, flags="S")
        try:
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:  # SYN-ACK
                open_ports.append(port)
                # 发送RST关闭连接
                rst_pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=port, flags="R")
                sr1(rst_pkt, timeout=0.5, verbose=0)
        except Exception:
            continue
        # 实时显示进度百分比
        if idx % max(1, total_ports // 10) == 0 or idx == total_ports:
            percent = idx / total_ports * 100
            print(f"    - 扫描进度：{idx}/{total_ports} ({percent:.1f}%)")
    percent_open = len(open_ports) / total_ports * 100 if total_ports else 0
    print(f"[+] [SYN扫描] 扫描完成，开放端口：{open_ports if open_ports else '无'}")
    print(f"[+] [SYN扫描] 成功率：{percent_open:.1f}%（{len(open_ports)}/{total_ports}）")
    return open_ports

if __name__ == "__main__":
    integrated_network_detection()