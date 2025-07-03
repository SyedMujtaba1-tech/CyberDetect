import pandas as pd
import sqlite3
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

# ========================
# 1. SETUP DATABASE
# ========================
conn = sqlite3.connect('phishing.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS detections
               (email_text TEXT, 
                prediction TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

# ========================
# 2. LOAD DATA
# ========================
try:
    data = pd.read_csv("emails.csv")
    print("✔ Training data loaded")
except:
    # Create default data if missing
    default_data = {
        "text": [
            "Your account needs verification",
            "Meeting at 3pm tomorrow",
            "Claim your free prize now!",
            "Monthly report attached"
        ],
        "label": ["phishing", "legitimate", "phishing", "legitimate"]
    }
    data = pd.DataFrame(default_data)
    data.to_csv("emails.csv", index=False)
    print("ℹ Created default emails.csv")

# ========================
# 3. TRAIN MODEL
# ========================
vectorizer = TfidfVectorizer(max_features=500)
X = vectorizer.fit_transform(data["text"])
y = data["label"]
model = RandomForestClassifier(n_estimators=50)
model.fit(X, y)

# ========================
# 4. DETECTION FUNCTION
# ========================
def detect_phishing(email):
    if not email.strip():
        return "empty"
    
    features = vectorizer.transform([email])
    prediction = model.predict(features)[0]
    
    # Save to database
    cursor.execute(
        "INSERT INTO detections (email_text, prediction) VALUES (?, ?)",
        (email, prediction)
    )
    conn.commit()
    
    return prediction

# ========================
# 5. COMMAND-LINE INTERFACE
# ========================
print("\n=== CyberDetect Phishing Detector ===")
print("Type 'quit' to exit | 'report' for stats\n")

while True:
    email = input("Enter email text: ").strip()
    
    if email.lower() == 'quit':
        break
        
    if email.lower() == 'report':
        counts = cursor.execute("SELECT prediction, COUNT(*) FROM detections GROUP BY prediction").fetchall()
        print("\n=== Stats ===")
        for pred, count in counts:
            print(f"{pred.upper()}: {count} emails")
        continue
    
    result = detect_phishing(email)
    print(f"Result: {result.upper()}")
    
    # Optional feedback
    feedback = input("Was this correct? (y/n): ").lower()
    if feedback == 'n':
        with open('feedback.csv', 'a') as f:
            f.write(f'"{email}","{"phishing" if result == "legitimate" else "legitimate"}"\n')
        print("✓ Feedback saved!")

conn.close()