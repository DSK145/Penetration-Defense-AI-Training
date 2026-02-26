# -*- coding: utf-8 -*-
"""
小工具：检测 Python 源文件编码并在必要时备份后重写为 UTF-8。
备份文件以 .bak 结尾保存原始字节。
依赖：chardet（可选，失败时回退到 cp936/gbk）。
"""
import io
import os
import shutil

try:
    import chardet
except Exception:
    chardet = None

def ensure_utf8(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            data = f.read()
        # 已经是 utf-8 则直接返回
        try:
            data.decode("utf-8")
            return True
        except UnicodeDecodeError:
            pass
        # 检测编码（有 chardet 时优先使用）
        enc = None
        if chardet:
            res = chardet.detect(data)
            enc = res.get("encoding")
            if not enc or res.get("confidence", 0) < 0.6:
                enc = None
        if not enc:
            # 常见回退：Windows 中文编码
            enc = "cp936"
        text = data.decode(enc, errors="replace")
        # 备份并以 UTF-8 重写
        shutil.copy2(path, path + ".bak")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return True
    except Exception:
        return False
