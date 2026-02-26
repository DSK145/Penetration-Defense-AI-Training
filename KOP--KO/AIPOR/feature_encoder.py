# -*- coding: utf-8 -*-
from typing import Dict, Tuple, Union
import numpy as np
import pickle
import os
from sklearn.preprocessing import StandardScaler, OneHotEncoder

class FeatureEncoder:
    def __init__(self, feature_dim: Dict[str, int], cache_path: str = None):
        self.feature_dim = feature_dim.copy()
        self.cache_path = cache_path
        self.slices = self._calc_slices(self.feature_dim)
        self.scalers = {}
        self.encoders = {}
        self.feature_type = {}
        for k in self.feature_dim.keys():
            if k in ("meta", "pe", "entropy", "memory"):
                self.feature_type[k] = "numeric"
            else:
                self.feature_type[k] = "categorical"
        self.is_fitted = False

    def _calc_slices(self, fd: Dict[str,int]) -> Dict[str, Tuple[int,int]]:
        slices = {}
        start = 0
        for k, v in fd.items():
            slices[k] = (start, start+v)
            start += v
        return slices

    def fit(self, X: np.ndarray):
        if X.ndim != 2:
            raise ValueError("X must be 2D numpy array")
        for feat_name, (s,e) in self.slices.items():
            slice_data = X[:, s:e]
            if self.feature_type.get(feat_name, "numeric") == "numeric":
                scaler = StandardScaler()
                try:
                    scaler.fit(slice_data.astype(float))
                except Exception:
                    scaler.fit(np.nan_to_num(slice_data).astype(float))
                self.scalers[feat_name] = scaler
            else:
                enc = OneHotEncoder(handle_unknown="ignore", sparse=False)
                try:
                    enc.fit(slice_data.astype(str))
                except Exception:
                    enc.fit(np.nan_to_num(slice_data).astype(str))
                self.encoders[feat_name] = enc
        self.is_fitted = True
        if self.cache_path:
            self.save_cache(self.cache_path)
        return self

    def transform(self, X: Union[np.ndarray, Dict[str, list]]):
        if not self.is_fitted:
            raise ValueError("encoder not fitted")
        if isinstance(X, dict):
            arr = []
            for k in self.feature_dim.keys():
                v = X.get(k, [0.0]*self.feature_dim[k])
                if isinstance(v, list):
                    arr.extend(v[:self.feature_dim[k]] + [0]*(self.feature_dim[k]-len(v)))
                else:
                    arr.extend(list(v)[:self.feature_dim[k]])
            X = np.array(arr, dtype=float).reshape(1, -1)
        out_slices = []
        for feat_name, (s,e) in self.slices.items():
            slice_data = X[:, s:e]
            if self.feature_type.get(feat_name, "numeric") == "numeric":
                scaler = self.scalers.get(feat_name)
                out = slice_data.astype(float) if scaler is None else scaler.transform(slice_data.astype(float))
            else:
                enc = self.encoders.get(feat_name)
                out = slice_data.astype(float) if enc is None else enc.transform(slice_data.astype(str))
            target_w = e - s
            if out.shape[1] < target_w:
                pad = np.zeros((out.shape[0], target_w - out.shape[1]))
                out = np.hstack([out, pad])
            elif out.shape[1] > target_w:
                out = out[:, :target_w]
            out_slices.append(out)
        return np.hstack(out_slices) if out_slices else X

    def fit_transform(self, X):
        self.fit(X)
        return self.transform(X)

    def save_cache(self, path: str):
        try:
            with open(path, 'wb') as f:
                pickle.dump({
                    "feature_dim": self.feature_dim,
                    "slices": self.slices,
                    "scalers": self.scalers,
                    "encoders": self.encoders,
                    "feature_type": self.feature_type,
                    "is_fitted": self.is_fitted
                }, f)
            return True
        except Exception:
            return False

    def load_cache(self, path: str):
        if not os.path.exists(path):
            return False
        try:
            with open(path, 'rb') as f:
                data = pickle.load(f)
            self.feature_dim = data["feature_dim"]
            self.slices = data["slices"]
            self.scalers = data["scalers"]
            self.encoders = data["encoders"]
            self.feature_type = data["feature_type"]
            self.is_fitted = data.get("is_fitted", False)
            return True
        except Exception:
            return False