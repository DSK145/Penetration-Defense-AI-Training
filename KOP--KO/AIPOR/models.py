# -*- coding: utf-8 -*-
import os
import pickle
import json
import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestClassifier
from config import CACHE_PATHS, TOTAL_FEAT_DIM, INIT_ALGORITHM_WEIGHTS, TRAIN_PARAMS
from logger import logger

class MalwareGAN(nn.Module):
    def __init__(self, input_dim=TOTAL_FEAT_DIM):
        super().__init__()
        self.generator = nn.Sequential(
            nn.Linear(input_dim, 512), nn.ReLU(),
            nn.Linear(512, input_dim), nn.Tanh()
        )
        self.device = torch.device("cpu")

    def generate_malware_features(self, num_samples=10, output_dim=None):
        output_dim = output_dim or TOTAL_FEAT_DIM
        with torch.no_grad():
            z = torch.randn(num_samples, TOTAL_FEAT_DIM)
            out = self.generator(z).cpu().numpy()
        out = (out + 1.0) / 2.0
        if out.shape[1] != output_dim:
            padded = np.zeros((out.shape[0], output_dim))
            padded[:, :min(output_dim, out.shape[1])] = out[:, :min(output_dim, out.shape[1])]
            return padded
        return out

class AdvancedEnsembleModel:
    def __init__(self, feature_encoder=None):
        self.feature_encoder = feature_encoder
        self.models = {"rf": RandomForestClassifier(n_estimators=100, n_jobs=1)}
        self.weights = INIT_ALGORITHM_WEIGHTS.copy()
        self.is_trained = False

    def train(self, X, y):
        if X is None or len(X) == 0:
            raise ValueError("训练数据为空")
        self.models["rf"].fit(X, y)
        self.is_trained = True
        self.save_cache()

    def predict(self, X):
        if not self.is_trained:
            raise ValueError("模型未训练")
        return self.models["rf"].predict_proba(X)[:,1]

    def save_cache(self):
        try:
            data = {"models": {"rf": self.models["rf"]}, "weights": self.weights}
            with open(CACHE_PATHS["ml_models"], 'wb') as f:
                pickle.dump(data, f)
            logger.info("模型缓存已保存")
        except Exception as e:
            logger.warning("模型缓存保存失败: %s", e)

    def load_cache(self):
        if os.path.exists(CACHE_PATHS["ml_models"]):
            try:
                with open(CACHE_PATHS["ml_models"], 'rb') as f:
                    d = pickle.load(f)
                if "rf" in d.get("models", {}):
                    self.models["rf"] = d["models"]["rf"]
                self.weights = d.get("weights", self.weights)
                self.is_trained = True
                logger.info("加载模型缓存成功")
            except Exception as e:
                logger.warning("加载模型缓存失败: %s", e)