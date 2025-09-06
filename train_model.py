import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold, cross_val_score, cross_validate
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# carica dataset
df = pd.read_csv("traffic.csv")

# colonne da usare come feature
X = df.drop(columns=["timestamp", "dpid", "mac", "class"])
y = LabelEncoder().fit_transform(df["class"])  # 0 = attacco, 1 = normale

# crea modello
clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)

# cross validation
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

scoring = ["accuracy", "precision", "recall", "f1"]

results = cross_validate(clf, X, y, cv=cv, scoring=scoring, return_train_score=False)

# stampa risultati
print("\n=== Cross Validation (5-fold) ===")
for metric in scoring:
    print(f"{metric.capitalize():<10}: {results[f'test_{metric}'].mean():.4f} "
          f"(± {results[f'test_{metric}'].std():.4f})")

# allena il modello finale su tutto il dataset
clf.fit(X, y)

# stampa importanza delle feature
importances = pd.Series(clf.feature_importances_, index=X.columns)
print("\nFeature Importances:")
print(importances.sort_values(ascending=False))

# salva modello
import joblib
joblib.dump(clf, "dos_ddos_detector.pkl")
print("\n[INFO] Modello salvato")

