import requests
import re
import os
os.makedirs("nvd_cve", exist_ok=True)
# 获取所有年份的CVE文件链接
response = requests.get("https://nvd.nist.gov/vuln/data-feeds#json_feed")
cve_urls = re.findall(r"nvdcve-1.1-(\d{4})\.json\.zip", response.text)
# 下载每个年份的CVE文件（CVA可解析其中的MD5/SHA特征）
for year in cve_urls:
    url = f"https://static.nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip"
    file_name = f"nvd_cve/nvdcve-1.1-{year}.json.zip"
    with open(file_name, "wb") as f:
        f.write(requests.get(url, stream=True).content)
    print(f"下载完成：{file_name}")