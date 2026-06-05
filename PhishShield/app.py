from flask import Flask, request, jsonify
from detector import cal_score,parser_input

app = Flask(__name__)
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        text = data.get("text", "")
        
        parsed=parser_input(text)
        result=cal_score(parsed)

        return jsonify(result)

    except Exception as e:
        print("BACKEND ERROR:", e)
        return jsonify({"error": str(e)})
@app.route("/")
def home():
    return "PhishShield AI API is running"

if __name__ == "__main__":
    app.run(debug=False)