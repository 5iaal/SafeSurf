import pandas as pd
import pickle
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report

DATASET_PATH = "backend/datasets/phishing_dataset.csv"
MODEL_PATH = "backend/models/url_ml_model.pkl"

def train():

    print("[+] Loading dataset...")
    df = pd.read_csv(DATASET_PATH)

    df = df.dropna()
    df['url'] = df['url'].astype(str)
    df['label'] = df['label'].str.lower()

    # تحويل النصوص لأرقام داخليًا
    df['label'] = df['label'].map({
        "legitimate": 0,
        "phishing": 1
    })

    X_train, X_test, y_train, y_test = train_test_split(
        df['url'],
        df['label'],
        test_size=0.2,
        random_state=42
    )

    print("[+] Vectorizing URLs...")
    vectorizer = TfidfVectorizer(
        max_features=15000,
        ngram_range=(1,2),
        analyzer="char_wb"
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print("[+] Training model...")
    model = GradientBoostingClassifier()
    model.fit(X_train_vec, y_train)

    print("[+] Evaluating...")
    preds = model.predict(X_test_vec)
    print(classification_report(y_test, preds))

    os.makedirs("backend/models", exist_ok=True)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump((model, vectorizer), f)

    print("[✓] Model saved successfully!")

if __name__ == "__main__":
    train()