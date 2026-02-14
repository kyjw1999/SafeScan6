import json

import joblib


def main() -> None:
    model = joblib.load("model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")

    terms = vectorizer.get_feature_names_out().tolist()
    idf = vectorizer.idf_.tolist()

    data = {
        "vectorizer": {
            "analyzer": vectorizer.analyzer,
            "lowercase": bool(vectorizer.lowercase),
            "ngram_range": list(vectorizer.ngram_range),
            "token_pattern": vectorizer.token_pattern,
            "norm": vectorizer.norm,
            "use_idf": bool(vectorizer.use_idf),
            "smooth_idf": bool(vectorizer.smooth_idf),
            "sublinear_tf": bool(vectorizer.sublinear_tf),
            "terms": terms,
            "idf": idf,
        },
        "model": {
            "type": type(model).__name__,
            "classes": [int(x) for x in model.classes_.tolist()],
            "coef": [float(x) for x in model.coef_[0].tolist()],
            "intercept": float(model.intercept_[0]),
        },
    }

    with open("offline/model.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")

    js = "window.SAFESCAN_MODEL = " + json.dumps(data, ensure_ascii=False, separators=(",", ":")) + ";\n"
    with open("offline/model.js", "w", encoding="utf-8") as f:
        f.write(js)

    print(f"Exported offline model: {len(terms)} features")


if __name__ == "__main__":
    main()

