import threading
import time
import psutil
from datetime import datetime
from typing import Optional, Dict, Any, List

class DynamicAnalyzer:
    def __init__(self, sensitive_apis: Optional[List[str]] = None):
        self.sensitive_apis = sensitive_apis or [
            "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
            "SetWindowsHookEx", "GetAsyncKeyState", "RegSetValue",
            "CreateService", "OpenProcess", "TerminateProcess",
            "CryptEncrypt", "CryptDecrypt", "InternetOpenUrl"
        ]
        self.process_monitor: Dict[int, Dict[str, Any]] = {}
        self.network_connections: List[Dict[str, Any]] = []
        self.file_ops: List[Dict[str, Any]] = []
        self.suspicious_behaviors: List[Dict[str, Any]] = []
        self._running = False
        self._thread = None
        self._lock = threading.RLock()

    def start(self, target_pid: Optional[int] = None):
        if self._running:
            return False
        self._running = True
        self._thread = threading.Thread(target=self._loop, args=(target_pid,), daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout: float = 5.0):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _loop(self, target_pid: Optional[int] = None):
        while self._running:
            try:
                self._sample_processes(target_pid)
                self._sample_network()
                self._sample_file_ops()
                self._detect_suspicious()
                time.sleep(1.0)
            except Exception:
                time.sleep(1.0)

    def _sample_processes(self, target_pid: Optional[int]):
        with self._lock:
            now = datetime.now()
            procs = {}
            for p in psutil.process_iter(['pid','name','cpu_percent','memory_info','num_threads']):
                try:
                    pid = p.info['pid']
                    if target_pid and pid != target_pid:
                        continue
                    procs[pid] = {
                        'name': p.info['name'],
                        'cpu': p.info.get('cpu_percent', 0.0),
                        'mem_mb': (p.info.get('memory_info').rss / 1024.0 / 1024.0) if p.info.get('memory_info') else 0.0,
                        'threads': p.info.get('num_threads', 0),
                        'timestamp': now
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            self.process_monitor = procs

    def _sample_network(self):
        with self._lock:
            conns = []
            for c in psutil.net_connections(kind='inet'):
                if c.status == 'ESTABLISHED' and c.raddr:
                    conns.append({
                        'pid': c.pid,
                        'laddr': f"{getattr(c.laddr, 'ip', '')}:{getattr(c.laddr, 'port', '')}",
                        'raddr': f"{getattr(c.raddr, 'ip', '')}:{getattr(c.raddr,'port','')}",
                        'status': c.status,
                        'timestamp': datetime.now()
                    })
            self.network_connections = conns

    def _sample_file_ops(self):
        with self._lock:
            ops = []
            for proc in psutil.process_iter(['pid','name']):
                try:
                    for f in proc.open_files():
                        ops.append({
                            'pid': proc.info['pid'],
                            'proc_name': proc.info['name'],
                            'file': f.path,
                            'timestamp': datetime.now()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            self.file_ops = ops

    def _detect_suspicious(self):
        with self._lock:
            for pid, info in self.process_monitor.items():
                score = 0
                indicators = []
                if info['cpu'] and info['cpu'] > 80:
                    score += 20; indicators.append("high_cpu")
                if info['mem_mb'] and info['mem_mb'] > 500:
                    score += 20; indicators.append("high_mem")
                if info['threads'] and info['threads'] > 80:
                    score += 10; indicators.append("many_threads")
                net_count = sum(1 for n in self.network_connections if n['pid']==pid)
                if net_count > 10:
                    score += 15; indicators.append("many_connections")
                if score >= 40:
                    item = {
                        'pid': pid,
                        'name': info.get('name'),
                        'score': score,
                        'indicators': indicators,
                        'timestamp': datetime.now()
                    }
                    if item not in self.suspicious_behaviors:
                        self.suspicious_behaviors.append(item)

    def get_report(self) -> Dict[str, Any]:
        with self._lock:
            report = {
                "timestamp": datetime.now().isoformat(),
                "process_count": len(self.process_monitor),
                "suspicious_behaviors": list(self.suspicious_behaviors),
                "recent_network": self.network_connections[-20:],
                "recent_files": self.file_ops[-20:]
            }
            return report

    def execute_in_sandbox(self, command: list, timeout: int = 30) -> Dict[str, Any]:
        import subprocess
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            return {
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "timeout": False
            }
        except subprocess.TimeoutExpired:
            return {"error": "timeout", "timeout": True}
        except Exception as e:
            return {"error": str(e)}