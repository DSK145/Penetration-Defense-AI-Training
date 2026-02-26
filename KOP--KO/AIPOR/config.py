# -*- coding: utf-8 -*-
import os
from datetime import datetime

# 根目录，用于缓存和生成的文件
ROOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "MalwareDetectionSystem")
os.makedirs(ROOT_DIR, exist_ok=True)

# 为避免源文件中包含平台/区域性的非 UTF-8 字符，
# 所有外部路径默认从环境变量读取，回退到 ASCII 安全的默认值。
# 这样可以防止源文件编码不一致导致的解析错误，同时保持可配置性。
SAMPLE_CONFIG = {
    "malware": os.environ.get("MALWARE_PATH", r"E:\\KOP--KO\\KOP--KO\\DDOS\\dsa"),
    "benign": os.environ.get("BENIGN_PATH", r"E:\\benign"),
    "pypi_malware": os.environ.get("PYPI_MALWARE_PATH", r"E:\\KOP--KO\\KOP--KO\\DDOS\\dsa\\2025-11-11-amazon-test"),
    "memory_malware": os.environ.get("MEMORY_MALWARE_PATH", r"E:\\KOP--KO\\KOP--KO\\DDOS\\dsa\\memory_malware"),
    "virus_libs": os.environ.get("VIRUS_LIBS_PATH", r"E:\\KOP--KO\\KOP--KO\\DDOS\\AIPOR\\MD5SHA256"),
    "opensource_libs": os.environ.get("OPENSOURCE_LIBS_PATH", r"E:\\KOP--KO\\KOP--KO\\DDOS\\AIPOR\\PyPI"),
}

CACHE_PATHS = {
    "dl_model": os.path.join(ROOT_DIR, "dl_model_cache.pth"),
    "ml_models": os.path.join(ROOT_DIR, "ml_models_cache.pkl"),
    "scaler": os.path.join(ROOT_DIR, "scaler_cache.pkl"),
    "feature_selector": os.path.join(ROOT_DIR, "feature_selector_cache.pkl"),
    "dynamic_weights": os.path.join(ROOT_DIR, "dynamic_weights_cache.json"),
    "encoder": os.path.join(ROOT_DIR, "feature_encoder_cache.pkl"),
    "decoder": os.path.join(ROOT_DIR, "result_decoder_cache.json"),
    "gan": os.path.join(ROOT_DIR, "malware_gan_cpu.pth"),
}

FEATURE_DIM = {
    "hash": 256, "meta": 64, "pe": 128, "string": 64,
    "entropy": 32, "ngram": 128, "api": 64, "behavior": 64,
    "pypi": 32, "memory": 32
}
TOTAL_FEAT_DIM = sum(FEATURE_DIM.values())

TRAIN_PARAMS = {
    "batch_size": 16,
    "epochs": 50,
    "lr": 3e-4,
    "random_state": 42,
    "early_stopping_patience": 10,
    "k_fold": 3
}

INIT_ALGORITHM_WEIGHTS = {
    "dl": 0.35, "rf": 0.20, "gb": 0.15, "et": 0.10, "knn": 0.07, "ada": 0.05
}

CPU_CORES = os.cpu_count() or 4