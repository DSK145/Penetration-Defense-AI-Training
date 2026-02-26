# -*- coding: utf-8 -*-
from typing import Dict, List
from collections import defaultdict
import json
import os

DEFAULT_BEHAVIOR_DB = {
    "ransomware": [
        ["encrypt files", "delete shadow copies", "create ransom note"],
        ["encrypt documents", "kill backup processes", "display ransom UI"]
    ],
    "trojan": [
        ["reverse shell", "c2 connect", "execute remote commands"],
        ["persistence via registry", "create startup service", "hide process"]
    ],
    "fileless": [
        ["memory-resident", "powershell execution", "no disk footprint"],
        ["reflective dll injection", "process hollowing", "in-memory payload"]
    ],
    "cryptominer": [
        ["cpu mining", "connect to mining pool", "hide process"],
        ["gpu mining", "submit mining shares", "hide network traffic"]
    ],
    "pypi_malware": [
        ["typo squatting", "post-install script", "steal pip credentials"]
    ],
    "data_stealer": [
        ["keylogger", "screenshot", "collect credentials", "upload data"]
    ]
}

class BehaviorLib:
    def __init__(self, db: Dict[str, List[List[str]]] = None, path: str = None):
        self.path = path
        self.db = db.copy() if db is not None else DEFAULT_BEHAVIOR_DB.copy()
        if path and os.path.exists(path):
            self.load(path)

    def load(self, path: str):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self.db.update(data)
        except Exception:
            pass

    def save(self, path: str = None):
        p = path or self.path
        if not p:
            return False
        try:
            with open(p, 'w', encoding='utf-8') as f:
                json.dump(self.db, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False

    def match_behavior_fingerprint(self, text: str) -> Dict[str, int]:
        res = defaultdict(int)
        if not text:
            return dict(res)
        lower = text.lower()
        for b_type, groups in self.db.items():
            for patterns in groups:
                match_count = sum(1 for p in patterns if p.lower() in lower)
                if match_count > 0:
                    res[b_type] += match_count
        return dict(res)