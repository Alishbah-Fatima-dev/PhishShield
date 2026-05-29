from flask import Flask, request, jsonify
from detector import cal_score

app = Flask(__name__)
@app.route("/")
def home():
    return "PhishShield AI API is running"

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    text = data.get("text", "")
    result = cal_score({
        "text": text,
        "urls": [],
        "emails": []
    })
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=False)