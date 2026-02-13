from __future__ import annotations

import json
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier

from dataset_loader import load_training_dataset
from preprocess import clean_text

SOURCE_SAMPLE_WEIGHTS = {
    # Keep user-curated and Arabic-focused rows influential.
    "messages": 4.0,
    "arabic_file": 3.5,
    "arabic_aug": 2.5,
    "spam_csv": 1.0,
    "url_dataset": 1.4,
    "phishing_urls": 1.8,
}
RANDOM_STATE = 42

TREE_MAX_ROWS = 45000
RF_MAX_ROWS = 50000
MLP_MAX_ROWS = 60000
SVD_COMPONENTS = 256


def _source_weights(source_series):
    return source_series.map(lambda s: SOURCE_SAMPLE_WEIGHTS.get(str(s), 1.0)).astype(float)


def _safe_preview(text: str, limit: int = 140) -> str:
    value = " ".join(str(text or "").split())
    if len(value) > limit:
        value = value[: limit - 3] + "..."
    return value.encode("ascii", errors="backslashreplace").decode("ascii")


def _print_error_examples(title: str, rows, true_label: int, pred_label: int) -> None:
    mask = (rows["true_label"] == true_label) & (rows["pred_label"] == pred_label)
    subset = rows[mask].copy()
    if subset.empty:
        print(f"{title}: none")
        return

    subset = subset.sort_values("unsafe_proba", ascending=(true_label == 1))
    print(f"{title}: {len(subset)}")
    for _, r in subset.head(8).iterrows():
        print(f"  - p(unsafe)={r['unsafe_proba']:.3f} | {_safe_preview(r['text'])}")


def _take_stratified_indices(y: np.ndarray, max_rows: int, random_state: int = RANDOM_STATE) -> np.ndarray:
    n = len(y)
    if n <= max_rows:
        return np.arange(n)

    rng = np.random.default_rng(random_state)
    indices = np.arange(n)
    selected = []

    for label in sorted(np.unique(y).tolist()):
        label_idx = indices[y == label]
        target = max(1, int(round(max_rows * (len(label_idx) / n))))
        target = min(target, len(label_idx))
        picked = rng.choice(label_idx, size=target, replace=False)
        selected.append(picked)

    merged = np.concatenate(selected)
    rng.shuffle(merged)
    if len(merged) > max_rows:
        merged = merged[:max_rows]
    return merged


def _unsafe_proba(model, X) -> np.ndarray:
    proba = model.predict_proba(X)
    classes = [int(c) for c in getattr(model, "classes_", [0, 1])]
    class_to_idx = {c: i for i, c in enumerate(classes)}
    unsafe_idx = class_to_idx.get(1, 1 if proba.shape[1] > 1 else 0)
    return np.asarray(proba[:, unsafe_idx], dtype=float)


def _evaluate(y_true: np.ndarray, proba_unsafe: np.ndarray) -> dict:
    pred = (proba_unsafe >= 0.5).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, pred, average="binary", zero_division=0
    )
    return {
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "confusion": confusion_matrix(y_true, pred, labels=[0, 1]).tolist(),
        "pred": pred,
    }


def _train_logreg(X_train, y_train, sample_weight):
    model = LogisticRegression(max_iter=2500, class_weight="balanced", random_state=RANDOM_STATE)
    model.fit(X_train, y_train, sample_weight=sample_weight)
    return model


def _train_decision_tree(X_train, y_train, sample_weight):
    model = DecisionTreeClassifier(
        class_weight="balanced",
        random_state=RANDOM_STATE,
        max_depth=44,
        min_samples_leaf=2,
    )
    model.fit(X_train, y_train, sample_weight=sample_weight)
    return model


def _train_random_forest(X_train, y_train, sample_weight):
    model = RandomForestClassifier(
        n_estimators=260,
        random_state=RANDOM_STATE,
        class_weight="balanced_subsample",
        min_samples_leaf=2,
        n_jobs=-1,
    )
    model.fit(X_train, y_train, sample_weight=sample_weight)
    return model


def _train_mlp(X_train_dense, y_train):
    model = MLPClassifier(
        hidden_layer_sizes=(192, 64),
        activation="relu",
        alpha=1e-4,
        learning_rate_init=0.001,
        max_iter=120,
        early_stopping=True,
        n_iter_no_change=8,
        validation_fraction=0.1,
        random_state=RANDOM_STATE,
    )
    model.fit(X_train_dense, y_train)
    return model


def _print_metric_block(name: str, metrics: dict) -> None:
    print(
        f"{name:<14} | acc={metrics['accuracy']:.4f} "
        f"prec={metrics['precision']:.4f} rec={metrics['recall']:.4f} f1={metrics['f1']:.4f} "
        f"cm={metrics['confusion']}"
    )


def main() -> None:
    data = load_training_dataset(".")
    data["text_clean"] = data["text"].astype(str).map(clean_text)
    data = data[data["text_clean"].str.len() > 0].copy()

    if data["label"].nunique() < 2:
        raise SystemExit("Training data must contain both safe(0) and unsafe(1) labels.")

    print("Dataset loaded.")
    print(f"Rows: {len(data)}")
    print(f"Labels: {data['label'].value_counts().to_dict()}")
    print(f"Sources: {data['source'].value_counts().to_dict()}")

    train_df, val_df = train_test_split(
        data,
        test_size=0.2,
        stratify=data["label"],
        random_state=RANDOM_STATE,
    )

    vectorizer = TfidfVectorizer(
        lowercase=True,
        token_pattern=r"(?u)\b\w\w+\b",
        ngram_range=(1, 2),
        max_features=14000,
    )
    X_train = vectorizer.fit_transform(train_df["text_clean"])
    X_val = vectorizer.transform(val_df["text_clean"])

    y_train = train_df["label"].astype(int).to_numpy()
    y_val = val_df["label"].astype(int).to_numpy()
    w_train = _source_weights(train_df["source"]).to_numpy(dtype=float)

    print("\nTraining models...")

    model_logreg = _train_logreg(X_train, y_train, w_train)

    tree_idx = _take_stratified_indices(y_train, TREE_MAX_ROWS)
    model_tree = _train_decision_tree(X_train[tree_idx], y_train[tree_idx], w_train[tree_idx])

    rf_idx = _take_stratified_indices(y_train, RF_MAX_ROWS)
    model_rf = _train_random_forest(X_train[rf_idx], y_train[rf_idx], w_train[rf_idx])

    mlp_idx = _take_stratified_indices(y_train, MLP_MAX_ROWS)
    n_components = max(32, min(SVD_COMPONENTS, X_train.shape[1] - 1))
    mlp_svd = TruncatedSVD(n_components=n_components, random_state=RANDOM_STATE)
    X_train_mlp = mlp_svd.fit_transform(X_train[mlp_idx])
    model_mlp = _train_mlp(X_train_mlp, y_train[mlp_idx])

    val_proba = {
        "logreg": _unsafe_proba(model_logreg, X_val),
        "decision_tree": _unsafe_proba(model_tree, X_val),
        "random_forest": _unsafe_proba(model_rf, X_val),
        "mlp": _unsafe_proba(model_mlp, mlp_svd.transform(X_val)),
    }

    metrics = {name: _evaluate(y_val, probs) for name, probs in val_proba.items()}

    print("\nValidation metrics:")
    _print_metric_block("Logistic", metrics["logreg"])
    _print_metric_block("DecisionTree", metrics["decision_tree"])
    _print_metric_block("RandomForest", metrics["random_forest"])
    _print_metric_block("MLP", metrics["mlp"])

    ensemble_raw_weights = {
        "logreg": max(metrics["logreg"]["f1"], 0.001),
        "decision_tree": max(metrics["decision_tree"]["f1"], 0.001),
        "random_forest": max(metrics["random_forest"]["f1"], 0.001),
        "mlp": max(metrics["mlp"]["f1"], 0.001),
    }
    total_w = float(sum(ensemble_raw_weights.values()))
    ensemble_weights = {k: float(v / total_w) for k, v in ensemble_raw_weights.items()}

    ensemble_proba = np.zeros_like(y_val, dtype=float)
    for name, probs in val_proba.items():
        ensemble_proba += ensemble_weights[name] * probs

    ensemble_metrics = _evaluate(y_val, ensemble_proba)
    metrics["ensemble"] = ensemble_metrics

    print("\nEnsemble (weighted by val F1):")
    _print_metric_block("Ensemble", ensemble_metrics)

    print("\nClassification report (ensemble):")
    print(
        classification_report(
            y_val,
            ensemble_metrics["pred"],
            digits=3,
            zero_division=0,
        )
    )

    mistakes = val_df[["text"]].copy().reset_index(drop=True)
    mistakes["true_label"] = y_val
    mistakes["pred_label"] = ensemble_metrics["pred"]
    mistakes["unsafe_proba"] = ensemble_proba

    print("Mistake analysis (ensemble):")
    _print_error_examples("False negatives (unsafe predicted safe)", mistakes, true_label=1, pred_label=0)
    _print_error_examples("False positives (safe predicted unsafe)", mistakes, true_label=0, pred_label=1)

    # Train final production artifacts on all rows.
    print("\nTraining final production artifacts on full dataset...")
    vectorizer_final = TfidfVectorizer(
        lowercase=True,
        token_pattern=r"(?u)\b\w\w+\b",
        ngram_range=(1, 2),
        max_features=14000,
    )
    X_all = vectorizer_final.fit_transform(data["text_clean"])
    y_all = data["label"].astype(int).to_numpy()
    w_all = _source_weights(data["source"]).to_numpy(dtype=float)

    final_logreg = _train_logreg(X_all, y_all, w_all)

    idx_tree_all = _take_stratified_indices(y_all, TREE_MAX_ROWS)
    final_tree = _train_decision_tree(X_all[idx_tree_all], y_all[idx_tree_all], w_all[idx_tree_all])

    idx_rf_all = _take_stratified_indices(y_all, RF_MAX_ROWS)
    final_rf = _train_random_forest(X_all[idx_rf_all], y_all[idx_rf_all], w_all[idx_rf_all])

    idx_mlp_all = _take_stratified_indices(y_all, MLP_MAX_ROWS)
    n_components_all = max(32, min(SVD_COMPONENTS, X_all.shape[1] - 1))
    final_mlp_svd = TruncatedSVD(n_components=n_components_all, random_state=RANDOM_STATE)
    X_all_mlp = final_mlp_svd.fit_transform(X_all[idx_mlp_all])
    final_mlp = _train_mlp(X_all_mlp, y_all[idx_mlp_all])

    # Backward-compatible artifacts used by existing scripts/offline export.
    joblib.dump(final_logreg, "model.pkl")
    joblib.dump(vectorizer_final, "vectorizer.pkl")

    ensemble_bundle = {
        "vectorizer": vectorizer_final,
        "models": {
            "logreg": final_logreg,
            "decision_tree": final_tree,
            "random_forest": final_rf,
            "mlp": final_mlp,
        },
        "mlp_svd": final_mlp_svd,
        "weights": ensemble_weights,
        "metadata": {
            "trained_at_utc": datetime.now(timezone.utc).isoformat(),
            "random_state": RANDOM_STATE,
            "source_weights": SOURCE_SAMPLE_WEIGHTS,
            "validation_metrics": {
                k: {
                    "accuracy": v["accuracy"],
                    "precision": v["precision"],
                    "recall": v["recall"],
                    "f1": v["f1"],
                    "confusion": v["confusion"],
                }
                for k, v in metrics.items()
            },
        },
    }
    joblib.dump(ensemble_bundle, "ensemble_models.pkl")

    report = {
        "rows": int(len(data)),
        "labels": {str(k): int(v) for k, v in data["label"].value_counts().to_dict().items()},
        "sources": {str(k): int(v) for k, v in data["source"].value_counts().to_dict().items()},
        "ensemble_weights": ensemble_weights,
        "metrics": {
            k: {
                "accuracy": v["accuracy"],
                "precision": v["precision"],
                "recall": v["recall"],
                "f1": v["f1"],
                "confusion": v["confusion"],
            }
            for k, v in metrics.items()
        },
    }
    with open("training_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write("\n")

    train_acc = float(final_logreg.score(X_all, y_all))
    print("\nSaved model.pkl, vectorizer.pkl, ensemble_models.pkl, training_report.json")
    print(f"Full-data Logistic training accuracy: {train_acc:.4f}")


if __name__ == "__main__":
    main()
