from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class TestHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if not event.is_directory:
            print(f"已检测到文件变动：{event.src_path}")

if __name__ == "__main__":
    observer = Observer()
    observer.schedule(TestHandler(), path="D:\\KOP--KO", recursive=True)
    observer.start()
    print("监控已启动，可在 D:\\KOP--KO 目录下新建/修改文件测试")
    while True:
        pass