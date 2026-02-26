# -*- coding: utf-8 -*-
import os
import re
import csv
import json
import pickle
import zlib
from collections import defaultdict
from config import SAMPLE_CONFIG, CACHE_PATHS, ROOT_DIR
from logger import logger

class MultiSourceVirusDatabase:
    def __init__(self):
        self.md5_db = set()
        self.sha256_db = set()
        self.opensource_feat_db = defaultdict(list)
        self.behavior_db = {}
    def load_csv_hash_file(self, path):
        md5_set, sha256_set = set(), set()
        md5_pat = re.compile(r'[0-9a-fA-F]{32}')
        sha256_pat = re.compile(r'[0-9a-fA-F]{64}')
        try:
            with open(path, 'rb') as f:
                text = f.read().decode('utf-8', errors='ignore')
            md5_set.update(m.lower() for m in md5_pat.findall(text))
            sha256_set.update(s.lower() for s in sha256_pat.findall(text))
        except Exception as e:
            logger.warning("Failed to read hash file %s: %s", path, e)
        return md5_set, sha256_set

    def match_opensource_features(self, file_path, file_content=None):
        matches = defaultdict(list)
        file_name = os.path.basename(file_path).lower()
        if file_content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_content = f.read()
            except Exception:
                file_content = ""
        for k, v in self.opensource_feat_db.items():
            for pattern in v:
                if pattern in file_name or pattern in file_content:
                    matches[k].append(pattern)
        return dict(matches)