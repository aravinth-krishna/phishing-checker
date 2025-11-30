import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.utils.class_weight import compute_class_weight
import joblib
import numpy as np
from urllib.parse import urlparse

df = pd.read_csv("phishing_kaggle_dataset.csv")

# ---------------------------------------
# 32 RESEARCHED FEATURES
# ---------------------------------------
selected_features = [
    "NumDots","SubdomainLevel","PathLevel","UrlLength","NumDash",
    "NumDashInHostname","AtSymbol","NumNumericChars","NoHttps","IpAddress",
    "NumQueryComponents","NumUnderscore","NumPercent","NumAmpersand",
    "NumHash","RandomString","DoubleSlashInPath","NumSensitiveWords",
    "EmbeddedBrandName","PctExtHyperlinks","PctExtResourceUrls",
    "InsecureForms","ExtFormAction","AbnormalFormAction",
    "PctNullSelfRedirectHyperlinks","RightClickDisabled","PopUpWindow",
    "SubmitInfoToEmail","IframeOrFrame","MissingTitle",
    "AbnormalExtFormActionR","PctExtNullSelfRedirectHyperlinksRT"
]

# ---------------------------------------
# FEATURE AUTO-GENERATION IF NOT IN CSV
# ---------------------------------------
if not set(selected_features).issubset(df.columns):
    print("⚠️ Columns missing → generating all features from URL…")

    def extract_all(url):
        u = str(url).lower()
        p = urlparse(u)
        host = p.hostname or ""

        return pd.Series({
            "NumDots": u.count("."),
            "SubdomainLevel": host.count("."),
            "PathLevel": u.count("/") - 2,
            "UrlLength": len(u),
            "NumDash": u.count("-"),
            "NumDashInHostname": host.count("-"),
            "AtSymbol": 1 if "@" in u else 0,
            "NumNumericChars": sum(c.isdigit() for c in u),
            "NoHttps": 0 if u.startswith("https://") else 1,
            "IpAddress": 1 if host.replace(".", "").isdigit() else 0,

            # Secondary features
            "NumQueryComponents": u.count("&"),
            "NumUnderscore": u.count("_"),
            "NumPercent": u.count("%"),
            "NumAmpersand": u.count("&"),
            "NumHash": u.count("#"),
            "RandomString": 1 if len(host) > 20 else 0,
            "DoubleSlashInPath": 1 if "//" in p.path else 0,
            "NumSensitiveWords": sum(k in u for k in ["login","verify","secure","update"]),

            # Fallback dataset-only features
            "EmbeddedBrandName": 0,
            "PctExtHyperlinks": 0,
            "PctExtResourceUrls": 0,
            "InsecureForms": 0,
            "ExtFormAction": 0,
            "AbnormalFormAction": 0,
            "PctNullSelfRedirectHyperlinks": 0,
            "RightClickDisabled": 0,
            "PopUpWindow": 0,
            "SubmitInfoToEmail": 0,
            "IframeOrFrame": 0,
            "MissingTitle": 0,
            "AbnormalExtFormActionR": 0,
            "PctExtNullSelfRedirectHyperlinksRT": 0
        })

    df[selected_features] = df["URL"].apply(extract_all)

# ---------------------------------------
# CLEAN LABELS — FIXES YOUR CRASH
# ---------------------------------------

# Drop completely missing labels
df = df.dropna(subset=["CLASS_LABEL"])

# Convert labels safely:
# Acceptable values (any dataset):
#   1, -1, 0, "phishing", "legit", "good", "bad", etc.
label_map = {
    1: 1,
    -1: 0,
    0: 0,
    "good": 0,
    "legit": 0,
    "benign": 0,
    "phishing": 1,
    "malicious": 1,
    "bad": 1
}

df["LABEL"] = df["CLASS_LABEL"].apply(lambda x: label_map.get(x, np.nan))
df = df.dropna(subset=["LABEL"])  # Remove unmapped
y = df["LABEL"].astype(int)

# Ensure no NaN remains in features
X = df[selected_features].fillna(0)

# ---------------------------------------
# TRAINING
# ---------------------------------------
cw = compute_class_weight(class_weight="balanced", classes=np.array([0, 1]), y=y)

class_weights = {0: cw[0], 1: cw[1]}

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(
    n_estimators=500,
    class_weight=class_weights,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

pred = model.predict(X_test)
proba = model.predict_proba(X_test)[:, 1]

print("✅ Accuracy:", accuracy_score(y_test, pred))
print(classification_report(y_test, pred))
print("Avg phishing probability:", np.mean(proba))

joblib.dump((model, selected_features), "model.joblib")
print("🎯 Model saved with 32-feature enhanced model.")
