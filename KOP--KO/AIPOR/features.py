import os
# ,MZ???L?This program cannot be run in DOS mode.PE 因为UTF-8检查MZ魔数或者PE头
import math
import numpy as np
from config import FEATURE_DIM, TOTAL_FEAT_DIM
from logger import logger
import pefile
from behavior_lib import BehaviorLib
from difflib import SequenceMatcher
from collections import Counter

behavior_lib = BehaviorLib()

def normalize_feature(feature, target_dim):
    a = np.array(feature, dtype=np.float32)
    if a.size == 0:
        return np.zeros(target_dim, dtype=np.float32)
    if a.size < target_dim:
        a = np.pad(a, (0, target_dim - a.size), mode='constant')
    else:
        a = a[:target_dim]
    mu = a.mean()
    sigma = a.std()
    return (a - mu) / (sigma + 1e-8) if sigma > 1e-6 else (a - mu)

def calculate_segment_entropy(file_path, segment_size=512*1024):
    try:
        entropies = []
        with open(file_path, 'rb') as f:
            while chunk := f.read(segment_size):
                if len(chunk) < 256:
                    break
                counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
                total = counts.sum()
                probs = counts[counts > 0] / total
                ent = - (probs * np.log2(probs + 1e-12)).sum()
                entropies.append(min(ent / 8.0, 1.0))
        return normalize_feature(entropies, FEATURE_DIM["entropy"])
    except Exception as e:
        logger.warning("计算分段熵失败 %s: %s", file_path, e)
        return np.zeros(FEATURE_DIM["entropy"], dtype=np.float32)

def extract_pe_features_enhanced(file_path):
    pe_feat = np.zeros(FEATURE_DIM["pe"], dtype=np.float32)
    try:
        if not file_path.lower().endswith(('.exe', '.dll', '.sys')):
            return pe_feat
        with open(file_path, 'rb') as f:
            if f.read(2) != b'MZ':
                return pe_feat
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()
        pe_feat[0] = getattr(pe.FILE_HEADER, "NumberOfSections", 0) / 32.0
        imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
        pe_feat[1] = (len(imports) if imports else 0) / 50.0
        pe.close()
    except Exception as e:
        logger.warning("PE特征提取异常 %s: %s", file_path, e)
    return normalize_feature(pe_feat, FEATURE_DIM["pe"])

def extract_single_feature_enhanced(file_path, multi_source_db=None):
    import hashlib
    total_feat = np.zeros(TOTAL_FEAT_DIM, dtype=np.float32)
    try:
        md5 = hashlib.md5()
        sha = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk); sha.update(chunk)
        md5hex = md5.hexdigest().lower()
        meta = np.zeros(FEATURE_DIM["meta"], dtype=np.float32)
        try:
            st = os.stat(file_path)
            meta[0] = min(st.st_size / (1024*1024), 1.0)
        except:
            pass
        pe = extract_pe_features_enhanced(file_path)
        entropy = calculate_segment_entropy(file_path)
        strv = np.zeros(FEATURE_DIM["string"], dtype=np.float32)
        try:
            with open(file_path, 'rb') as f:
                t = f.read(1024*1024).decode('utf-8', errors='ignore').lower()
            strv[0] = min(t.count("import") / 10.0, 1.0)
        except:
            pass
        total_feat = np.concatenate([np.zeros(FEATURE_DIM["hash"]), meta, pe, strv, entropy,
                                     np.zeros(FEATURE_DIM["ngram"]), np.zeros(FEATURE_DIM["api"]),
                                     np.zeros(FEATURE_DIM["behavior"]), np.zeros(FEATURE_DIM["pypi"]),
                                     np.zeros(FEATURE_DIM["memory"])])
        behavior_matches = {}
        opensource_matches = {}
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            behavior_matches = behavior_lib.match_behavior_fingerprint(content)
            if multi_source_db:
                opensource_matches = multi_source_db.match_opensource_features(file_path, content)
        except:
            pass
        return total_feat, md5hex, behavior_matches, opensource_matches
    except Exception as e:
        logger.warning("特征提取失败 %s: %s", file_path, e)
        return np.zeros(TOTAL_FEAT_DIM, dtype=np.float32), "", {}, {}