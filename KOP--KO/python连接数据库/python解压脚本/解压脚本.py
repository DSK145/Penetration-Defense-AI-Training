import libarchive
import os

def extract_archive(archive_path, password, extract_dir):
    """使用libarchive-c解压带密码的归档文件（支持ZIP、7Z等多种格式）"""
    os.makedirs(extract_dir, exist_ok=True)
    try:
        # 调用libarchive解压，传入密码
        libarchive.extract_file(archive_path, extract_dir, password=password)
        print(f"✅ 解压成功！文件已保存到: {extract_dir}")
    except Exception as e:
        print(f"❌ 解压失败: {str(e)}")
        print("可能原因：密码错误、文件格式不支持或文件损坏")

if __name__ == "__main__":
    print("=" * 50)
    print("          基于libarchive的带密码解压工具 (Python版)")
    print("=" * 50)
    
    archive_path = input("\n1. 请输入归档文件（ZIP/7Z等）的完整路径：").strip()
    password = input("2. 请输入解压密码：").strip()
    extract_dir = input("3. 请输入解压目标文件夹路径：").strip()

    print("\n正在尝试解压...")
    extract_archive(archive_path, password, extract_dir)