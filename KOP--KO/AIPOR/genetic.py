# -*- coding: utf-8 -*-
from concurrent.futures import ThreadPoolExecutor, as_completed
import numpy as np
from typing import Callable

def _init_population(pop_size: int, dim: int, low=0.1, high=1.5):
    return np.random.uniform(low, high, size=(pop_size, dim))

def optimize_feature_weights(X,
                             y,
                             eval_fn: Callable[[np.ndarray], float],
                             pop_size: int = 30,
                             generations: int = 20,
                             crossover_prob: float = 0.7,
                             mutation_sigma: float = 0.08,
                             workers: int = 8):
    dim = X.shape[1]
    population = _init_population(pop_size, dim)
    best_weights = population[0].copy()
    best_score = -1.0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for gen in range(generations):
            futures = {pool.submit(eval_fn, ind): i for i, ind in enumerate(population)}
            scores = np.zeros(pop_size)
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    scores[idx] = float(fut.result())
                except Exception:
                    scores[idx] = -1.0
            cur_idx = int(np.argmax(scores))
            cur_best = scores[cur_idx]
            if cur_best > best_score:
                best_score = cur_best
                best_weights = population[cur_idx].copy()
            adj = scores - scores.min() + 1e-8
            probs = adj / (adj.sum() + 1e-12)
            indices = np.random.choice(pop_size, size=pop_size, p=probs)
            next_pop = population[indices].copy()
            for i in range(0, pop_size, 2):
                if i + 1 >= pop_size:
                    break
                if np.random.rand() < crossover_prob:
                    cp = np.random.randint(1, dim)
                    a, b = next_pop[i].copy(), next_pop[i+1].copy()
                    next_pop[i, cp:], next_pop[i+1, cp:] = b[cp:], a[cp:]
            mutations = np.random.normal(0, mutation_sigma, size=next_pop.shape)
            next_pop = next_pop + mutations
            population = np.clip(next_pop, 0.01, 2.0)
    return best_weights