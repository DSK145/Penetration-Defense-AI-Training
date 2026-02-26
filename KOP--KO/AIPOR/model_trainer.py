import torch
import torch.nn as nn
import torch.optim as optim
from torchtext.vocab import build_vocab_from_iterator
import time
import re
import pandas as pd
from pathlib import Path
from collections import defaultdict
from typing import List, Tuple

# 硬件加速自动初始化（不变）
def init_hardware_acceleration():
    if torch.cuda.is_available():
        device = torch.device("cuda")
        device_name = torch.cuda.get_device_name(0)
        acceleration_type = "NVIDIA GPU/CUDA"
    elif torch.backends.mps.is_available():
        device = torch.device("mps")
        device_name = "Apple Metal GPU"
        acceleration_type = "Metal GPU"
    elif hasattr(torch.backends, 'openvino') and torch.backends.openvino.is_available():
        device = torch.device("openvino")
        device_name = "Intel iGPU"
        acceleration_type = "Intel OpenVINO"
    else:
        device = torch.device("cpu")
        device_name = "CPU"
        acceleration_type = "CPU SIMD"
    
    print(f"======================================")
    print(f"✅ 硬件加速已启动！（支持双精度自动学习）")
    print(f"加速类型：{acceleration_type}")
    print(f"设备名称：{device_name}")
    print(f"当前设备：{device} | 数据类型：torch.float64（双精）")
    print(f"======================================")
    return device

# 文本预处理（不变）
def preprocess_text(text):
    text = str(text).lower().strip()
    text = re.sub(r'[^\w\s]', '', text)
    return text.split()

# 自动构建词汇表（不变）
def build_vocab(texts):
    def yield_tokens(texts):
        for text in texts:
            yield preprocess_text(text)
    vocab = build_vocab_from_iterator(yield_tokens(texts), specials=["<pad>", "<unk>"])
    vocab.set_default_index(vocab["<unk>"])
    return vocab

# 自动学习+语义理解模型（不变）
class AutoUnderstandingModel(nn.Module):
    def __init__(self, vocab_size, embedding_dim=128, hidden_dim=256, num_classes=2, dtype=torch.float64):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, dtype=dtype)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True, bidirectional=True, dtype=dtype)
        self.fc = nn.Linear(hidden_dim * 2, num_classes, dtype=dtype)
        self.dtype = dtype

    def forward(self, x):
        embed = self.embedding(x)
        lstm_out, _ = self.lstm(embed)
        cls_feat = lstm_out[:, -1, :]
        logits = self.fc(cls_feat)
        return logits

# 数据加载（不变）
def load_data(texts, labels, vocab, max_seq_len=32, device="cpu"):
    def encode_text(text):
        tokens = preprocess_text(text)
        ids = vocab(tokens)[:max_seq_len]
        ids += [vocab["<pad>"]] * (max_seq_len - len(ids))
        return torch.tensor(ids, dtype=torch.long, device=device)
    
    X = torch.stack([encode_text(text) for text in texts])
    y = torch.tensor(labels, dtype=torch.long, device=device)
    return X, y

# 单个文件加载（基础函数，不变）
def load_single_file(file_path: str, text_col="text", label_col="label") -> Tuple[List[str], List[int]]:
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"文件不存在：{file_path}")
    
    if file_path.suffix == ".csv":
        df = pd.read_csv(file_path)
    elif file_path.suffix == ".tsv":
        df = pd.read_csv(file_path, sep="\t")
    elif file_path.suffix == ".txt":
        df = pd.read_csv(file_path, sep="\t", names=[text_col, label_col])
    else:
        raise ValueError(f"不支持的文件格式：{file_path.suffix}，仅支持 CSV/TSV/TXT")
    
    if text_col not in df.columns or label_col not in df.columns:
        raise ValueError(f"文件需包含列：{text_col}（文本）和 {label_col}（标签）")
    
    texts = df[text_col].dropna().unique().tolist()
    labels = df[df[text_col].isin(texts)][label_col].astype(int).tolist()
    return texts, labels

# 新增：批量加载多个文件并合并
def load_multiple_files(file_list: List[str], text_col="text", label_col="label") -> Tuple[List[str], List[int]]:
    """
    批量加载多个数据文件，自动合并文本和标签
    :param file_list: 文件路径列表（如 ["data1.csv", "data2.tsv", "data3.txt"]）
    :return: 合并后的 texts, labels
    """
    all_texts = []
    all_labels = []
    
    for file in file_list:
        print(f"\n📄 正在加载文件：{file}")
        try:
            texts, labels = load_single_file(file, text_col, label_col)
            all_texts.extend(texts)
            all_labels.extend(labels)
            print(f"✅ 加载成功：{len(texts)} 条数据")
        except Exception as e:
            print(f"❌ 加载失败：{e}，跳过该文件")
    
    # 去重（避免多个文件中的重复文本）
    unique_texts = []
    unique_labels = []
    text_set = set()
    for text, label in zip(all_texts, all_labels):
        if text not in text_set:
            text_set.add(text)
            unique_texts.append(text)
            unique_labels.append(label)
    
    print(f"\n📊 批量加载完成：共 {len(unique_texts)} 条unique数据，{len(set(unique_labels))} 个类别")
    return unique_texts, unique_labels

# 自动学习流程（修改为支持多文件）
def auto_learn_and_understand(
    device,
    file_list: List[str] = ["train1.csv", "train2.tsv", "train3.txt"],  # 默认多文件列表
    text_col="text",
    label_col="label"
):
    # 1. 批量加载多个文件
    print(f"📂 启动批量数据加载：共 {len(file_list)} 个文件")
    try:
        train_texts, train_labels = load_multiple_files(file_list, text_col, label_col)
        if not train_texts:
            print(f"❌ 无有效数据加载，程序终止")
            return
    except Exception as e:
        print(f"❌ 批量加载异常：{e}")
        return
    
    # 2. 自动构建词汇表
    print(f"\n📚 启动自动特征学习：构建文本词汇表")
    vocab = build_vocab(train_texts)
    vocab_size = len(vocab)
    print(f"✅ 词汇表构建完成（规模：{vocab_size} 个词）")
    
    # 3. 加载数据（双精度适配）
    X_train, y_train = load_data(train_texts, train_labels, vocab, device=device)
    
    # 4. 初始化模型（动态适配类别数）
    num_classes = len(set(train_labels))
    model = AutoUnderstandingModel(vocab_size, num_classes=num_classes, dtype=torch.float64).to(device)
    criterion = nn.CrossEntropyLoss(dtype=torch.float64)
    optimizer = optim.Adam(model.parameters(), lr=1e-3)
    
    # 5. 自动训练
    print(f"\n⚡ 启动双精度自动训练（硬件加速，{num_classes} 分类，{len(train_texts)} 条数据）")
    epochs = 10
    model.train()
    start_time = time.perf_counter()
    
    for epoch in range(epochs):
        optimizer.zero_grad()
        outputs = model(X_train)
        loss = criterion(outputs, y_train)
        loss.backward()
        optimizer.step()
        
        if (epoch + 1) % 5 == 0:
            elapsed = time.perf_counter() - start_time
            print(f"Epoch [{epoch+1}/{epochs}] | 损失：{loss.item():.6f}（双精） | 耗时：{elapsed:.6f}秒")
    
    # 6. 示例测试（可替换为文件测试数据）
    test_texts = [
        "大语言模型能理解人类语言", "假期去海边度假",
        "深度学习优化模型性能", "今天的咖啡很美味",
        "自然语言处理技术持续进步", "周末和朋友去露营"
    ]
    X_test, _ = load_data(test_texts, [0]*len(test_texts), vocab, device=device)
    
    # 7. 自动理解推理
    model.eval()
    with torch.no_grad():
        infer_start = time.perf_counter()
        outputs = model(X_test)
        preds = torch.argmax(outputs, dim=1)
        infer_time = time.perf_counter() - infer_start
    
    # 8. 输出结果
    label_map = {i: f"类别{i}" for i in sorted(set(train_labels))}
    print(f"\n📈 自动理解结果（双精度推理耗时：{infer_time:.6f}