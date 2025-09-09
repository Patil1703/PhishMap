import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# Load dataset
data = pd.read_csv("dataset.csv")

# Features and target
X = data.drop(["Result", "index"], axis=1)   # Drop Result (target) and index
y = data["Result"]                           # Target column is Result

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = DecisionTreeClassifier(max_depth=5)
model.fit(X_train, y_train)

# --- Evaluate ---
y_pred = model.predict(X_test)

print("✅ Model trained and saved as phishing_model.pkl")
print("🔎 Accuracy:", accuracy_score(y_test, y_pred))
print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))
print("\n📉 Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Save model
joblib.dump(model, "phishing_model.pkl")
