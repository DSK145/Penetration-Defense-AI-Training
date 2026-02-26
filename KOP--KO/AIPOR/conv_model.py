# -*- coding: utf-8 -*-
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

class Conv2DNet(nn.Module):
    def __init__(self, H: int, W: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv2d(1, 16, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Conv2d(16, 32, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Flatten(),
            nn.Linear(32 * (H//4) * (W//4), 128),
            nn.ReLU(),
            nn.Linear(128, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.net(x)

class PyTorchConv2D:
    def __init__(self, H: int, W: int, device: str = "cpu"):
        self.H = H
        self.W = W
        self.device = torch.device(device)
        self.model = Conv2DNet(H, W).to(self.device)

    def _reshape(self, X: np.ndarray):
        n, f = X.shape
        total = self.H * self.W
        padded = np.zeros((n, total), dtype=np.float32)
        padded[:, :min(f, total)] = X[:, :min(f, total)]
        return padded.reshape(n, 1, self.H, self.W)

    def fit(self, X: np.ndarray, y: np.ndarray, epochs: int = 10, batch_size: int = 32, lr: float = 1e-3):
        Xc = self._reshape(X)
        Xt = torch.tensor(Xc, dtype=torch.float32, device=self.device)
        yt = torch.tensor(y.reshape(-1,1), dtype=torch.float32, device=self.device)
        ds = TensorDataset(Xt, yt)
        loader = DataLoader(ds, batch_size=batch_size, shuffle=True, num_workers=0)
        opt = optim.Adam(self.model.parameters(), lr=lr)
        criterion = nn.BCELoss()
        self.model.train()
        for epoch in range(epochs):
            loss_acc = 0.0
            for bx, by in loader:
                opt.zero_grad()
                pred = self.model(bx)
                loss = criterion(pred, by)
                loss.backward()
                opt.step()
                loss_acc += loss.item()

    def predict_proba(self, X: np.ndarray):
        self.model.eval()
        Xc = self._reshape(X)
        with torch.no_grad():
            xt = torch.tensor(Xc, dtype=torch.float32, device=self.device)
            out = self.model(xt).cpu().numpy().flatten()
        return out