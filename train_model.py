import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold, cross_val_score, cross_validate
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# === Carica dataset ===
df = pd.read_csv("traffic.csv")

# Colonne da usare come feature (togli timestamp, dpid, mac, class)
X = df.drop(columns=["timestamp", "dpid", "mac", "class"])
y = LabelEncoder().fit_transform(df["class"])  # 0 = attacco, 1 = normale

# === Modello ===
clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)

# === Cross Validation ===
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

scoring = ["accuracy", "precision", "recall", "f1"]

results = cross_validate(clf, X, y, cv=cv, scoring=scoring, return_train_score=False)

# === Stampa risultati ===
print("\n=== Cross Validation (5-fold) ===")
for metric in scoring:
    print(f"{metric.capitalize():<10}: {results[f'test_{metric}'].mean():.4f} "
          f"(± {results[f'test_{metric}'].std():.4f})")

# === Allena modello finale su tutto il dataset ===
clf.fit(X, y)

# === Importanza delle feature ===
importances = pd.Series(clf.feature_importances_, index=X.columns)
print("\nFeature Importances:")
print(importances.sort_values(ascending=False))

# === Salva modello ===
import joblib
joblib.dump(clf, "dos_ddos_detector.pkl")
print("\n[+] Modello salvato in dos_ddos_detector.pkl")

