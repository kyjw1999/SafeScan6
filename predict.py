import joblib

from preprocess import clean_text

model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


def predict_input(text: str):
    cleaned = clean_text(text)
    vec = vectorizer.transform([cleaned])

    prediction = int(model.predict(vec)[0])
    probability = float(model.predict_proba(vec).max())

    label = "Safe / آمن" if prediction == 0 else "Unsafe / غير آمن"
    return label, round(probability * 100, 2)

