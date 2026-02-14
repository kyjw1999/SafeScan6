import os

from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from dataset_loader import load_training_dataset
from preprocess import clean_text

SOURCE_SAMPLE_WEIGHTS = {
    "messages": 4.0,
    "spam_csv": 1.0,
}
RANDOM_STATE = 42


def main() -> None:
    try:
        import tensorflow as tf  # type: ignore
    except Exception as e:  # pragma: no cover
        raise SystemExit(
            "TensorFlow is not installed. Install it first (see requirements-tf.txt)."
        ) from e

    data = load_training_dataset(".")
    data["text_clean"] = data["text"].astype(str).map(clean_text)
    data = data[data["text_clean"].str.len() > 0]

    if data["label"].nunique() < 2:
        raise SystemExit("Training data must contain both safe(0) and unsafe(1) labels.")

    train_df, val_df = train_test_split(
        data,
        test_size=0.2,
        stratify=data["label"],
        random_state=RANDOM_STATE,
    )

    train_texts = train_df["text_clean"].astype(str).tolist()
    train_labels = train_df["label"].astype(int).tolist()
    val_texts = val_df["text_clean"].astype(str).tolist()
    val_labels = val_df["label"].astype(int).tolist()
    sample_weights = (
        train_df["source"].map(lambda s: SOURCE_SAMPLE_WEIGHTS.get(str(s), 1.0)).astype(float).tolist()
    )

    print("Dataset loaded.")
    print(f"Rows: {len(data)}")
    print(f"Labels: {data['label'].value_counts().to_dict()}")
    print(f"Sources: {data['source'].value_counts().to_dict()}")

    text_vec = tf.keras.layers.TextVectorization(
        max_tokens=20000,
        ngrams=2,
        output_mode="tf-idf",
    )
    text_vec.adapt(train_texts)

    model = tf.keras.Sequential(
        [
            text_vec,
            tf.keras.layers.Dense(32, activation="relu"),
            tf.keras.layers.Dropout(0.25),
            tf.keras.layers.Dense(1, activation="sigmoid"),
        ]
    )

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )

    callbacks = [
        tf.keras.callbacks.EarlyStopping(monitor="loss", patience=3, restore_best_weights=True)
    ]

    model.fit(
        train_texts,
        train_labels,
        sample_weight=sample_weights,
        validation_data=(val_texts, val_labels),
        epochs=25,
        batch_size=16,
        verbose=1,
        callbacks=callbacks,
    )

    val_pred = model.predict(val_texts, verbose=0).reshape(-1)
    val_pred_label = (val_pred >= 0.5).astype(int)
    print("\nValidation report (combined datasets):")
    print(classification_report(val_labels, val_pred_label, digits=3, zero_division=0))
    print("Confusion matrix [[tn, fp], [fn, tp]]:", confusion_matrix(val_labels, val_pred_label, labels=[0, 1]).tolist())

    out_dir = os.environ.get("SAFESCAN_TF_MODEL_DIR", "tf_model")
    model.save(out_dir)
    print(f"Saved TensorFlow model to: {out_dir}")


if __name__ == "__main__":
    main()
