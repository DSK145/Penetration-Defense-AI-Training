import sys
import traceback
import os

# ---- 在任何可能触发源码解析错误的 import 之前，尝试修复编码 ----
base_dir = os.path.dirname(__file__)
try:
    try:
        # 优先包内相对导入（当作为包运行时）
        from .encoding_fixer import ensure_utf8
    except Exception:
        # 回退到绝对导入（当直接以脚本运行时）
        import encoding_fixer as _ef
        ensure_utf8 = _ef.ensure_utf8

    for root, _, files in os.walk(base_dir):
        for name in files:
            if name.endswith(".py"):
                path = os.path.join(root, name)
                try:
                    ensure_utf8(path)
                except Exception:
                    sys.stderr.write(f"encoding fix failed for: {path}\n")
                    traceback.print_exc()
except Exception:
    # 不要阻止启动，记录到 stderr 便于排查
    traceback.print_exc()

# ---- 原始导入与主逻辑（示例） ----
import io
import tempfile
import shutil
import stat
import numpy as np
from logger import logger
from config import SAMPLE_CONFIG, FEATURE_DIM, TOTAL_FEAT_DIM
from db import MultiSourceVirusDatabase
from features import extract_single_feature_enhanced
from feature_encoder import FeatureEncoder
from models import AdvancedEnsembleModel, MalwareGAN

# 在程序启动时扫描仓库并将检测到的文本文件非 UTF-8 的文件转换为 UTF-8
def _is_binary(data: bytes) -> bool:
    # 简单二进制判断：包含 NUL 字节或大量非文本字节
    if b'\x00' in data:
        return True
    # 统计不可打印字符比例
    text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)))
    nontext = sum(1 for b in data if b not in text_chars)
    return (nontext / max(1, len(data))) > 0.30

def _try_decode(data: bytes, enc: str):
    try:
        return data.decode(enc)
    except Exception:
        return None

def ensure_utf8_for_all_files(root_dir: str, logger_obj=None, max_file_size=10 * 1024 * 1024):
    """
    遍历 root_dir 下所有文件，尝试把可识别为文本但不是 UTF-8 的文件转换为 UTF-8 编码。
    - 跳过明显的二进制文件（含 NUL 或高比例不可打印字符）
    - 跳过大于 max_file_size 的文件以避免意外转换大二进制文件
    - 尝试一系列常见编码进行解码：utf-8, utf-8-sig, utf-16{,-le,-be}, gb18030, gbk, cp1252, latin1
    """
    log = logger_obj or logger
    enc_candidates = ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "gb18030", "gbk", "cp1252", "latin1", "iso-8859-1","UTF-32","UTF-32LE","UTF-32BE"]
    converted = 0
    scanned = 0
    # UTF-8制动失效（无报错也没改变UTF-8错误）
    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            path = os.path.join(dirpath, fname)
            try:
                scanned += 1
                st = os.stat(path)
                # 跳过不可读或非常大的文件
                if not stat.S_ISREG(st.st_mode) or st.st_size > max_file_size:
                    continue
                with open(path, "rb") as f:
                    raw = f.read()
                if len(raw) == 0:
                    continue
                if _is_binary(raw):
                    continue
                # 尝试 utf-8 首解
                if _try_decode(raw, "utf-8") is not None:
                    continue  # 已是 UTF-8
                # 依次尝试候选编码
                decoded_text = None
                used_enc = None
                for enc in enc_candidates:
                    decoded = _try_decode(raw, enc)
                    if decoded is not None:
                        decoded_text = decoded
                        used_enc = enc
                        break
                if decoded_text is None:
                    log.warning("无法识别文本文件编码，跳过: %s", path)
                    continue
                # 将文本以 UTF-8 写回（保留行结束符，不做 normalize）
                # 原子写入
                dir_for_tmp = os.path.dirname(path)
                fd, tmp_path = tempfile.mkstemp(dir=dir_for_tmp)
                os.close(fd)
                with open(tmp_path, "wb") as outf:
                    outf.write(decoded_text.encode("utf-8"))
                # 保留原文件权限
                shutil.copymode(path, tmp_path)
                os.replace(tmp_path, path)
                converted += 1
                log.info("已将文件从 %s 转为 UTF-8: %s", used_enc, path)
            except Exception as e:
                log.warning("\u8b66\u544a: \u8bfb\u53d6\u683c\u5f0f\u6587\u4ef6\u5931\u8d25 %s: %s", path, e)
                # if tmp exists, try remove
                try:
                    if 'tmp_path' in locals() and os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
    log.info("编码检查完成，扫描文件数: %d，已转换数: %d", scanned, converted)
    return converted
def main(argv):
    # 先确保工作区源码文本文件为 UTF-8（repo 根目录往上两级）
    try:
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        ensure_utf8_for_all_files(repo_root, logger_obj=logger)
    except Exception as e:
        logger.warning("执行 UTF-8 自动转换时发生异常: %s", e)

    print("。。。。。")
    db = MultiSourceVirusDatabase()
    encoder = FeatureEncoder(FEATURE_DIM)
    model = AdvancedEnsembleModel(feature_encoder=encoder)
    sample_dir = SAMPLE_CONFIG.get("benign") or "."
    test_file = None
    for root, _, files in os.walk(sample_dir):
        for f in files:
            p = os.path.join(root, f)
            if os.path.getsize(p) > 1024:
                test_file = p
                break
        if test_file:
            break
    if not test_file:
        print("δ�ҵ����ʲ����ļ������� SAMPLE_CONFIG['benign']")
        return 0
    feat, md5, behaviors, opens = extract_single_feature_enhanced(test_file, multi_source_db=db)
    print(f"�����ļ�: {test_file} md5:{md5}")
    try:
        X = np.vstack([feat, feat + 0.01])
        y = np.array([0.0, 1.0])
        encoder.fit(X)
        X_enc = encoder.transform(X)
        model.train(X_enc, y)
        prob = model.predict(X_enc[:1])[0]
        print("Ԥ�����:", prob)
    except Exception as e:
        logger.warning("ʾ��ѵ��/Ԥ��ʧ��: %s", e)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))