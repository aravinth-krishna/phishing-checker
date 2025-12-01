from fastapi import FastAPI
from pydantic import BaseModel
import pandas as pd
import joblib
from fastapi.middleware.cors import CORSMiddleware

model, feature_cols = joblib.load("model.joblib")

app = FastAPI(title="Phishing URL Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class UrlFeatures(BaseModel):
    features: dict

@app.post("/predict")
def predict(data: UrlFeatures):

    incoming = data.features or {}

    full = {col: float(incoming.get(col, 0)) for col in feature_cols}
    df = pd.DataFrame([full], columns=feature_cols).astype(float)

    print("Incoming features from frontend:", incoming)
    print("Final model feature vector:", df.to_dict(orient="records"))

    proba = model.predict_proba(df)[0][1]

    label = "phishing" if proba >= 0.50 else "legitimate"

    return {"label": label, "score": float(proba)}
