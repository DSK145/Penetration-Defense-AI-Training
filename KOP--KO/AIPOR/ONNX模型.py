# -*- coding: utf-8 -*-

# 轻量入口兼向后兼容的桥接文件：
# 保持文件名以便兼容外部引用
# 将核心实现迁移到模块化代码（main.py）
from main import main

if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv))