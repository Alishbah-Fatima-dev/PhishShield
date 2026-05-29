import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
#------------Loading data------------------
data = pd.read_csv("phishing_dataset.csv")
print("Shape:", data.shape)
print(data.columns)
#---------------feature labeling-----------
X = data["text"]
y = data["label"]
#--------------train & test-----------------
X_train, X_test, y_train, y_test = train_test_split(
    X,y,
    test_size=0.2,
    random_state=42)
#------------TF-IDF Vectorization---------------
vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)
#---------------Model training---------------
model = LogisticRegression(max_iter=1000)
model.fit(X_train_vec, y_train)
#---------------Evaluation--------------------
accuracy = model.score(X_test_vec, y_test)
print("Accuracy:", accuracy)
#--------------sample prediction-------------
sample_text = [
    "Your bank account is locked, verify now",
    "Meeting scheduled tomorrow at 10am",
    "Click here to claim your reward prize"
]

sample_vec = vectorizer.transform(sample_text)
predictions = model.predict(sample_vec)
probabilities = model.predict_proba(sample_vec)
print("\nPredictions:", predictions)
print("\nProbabilities:\n", probabilities)

#-------------phishing risk score (0–100)--------------
phishing_score = probabilities[:, 1] * 100
print("\nPhishing Risk Scores:", phishing_score)

import joblib
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")
