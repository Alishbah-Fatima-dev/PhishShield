from flask import Flask, request, jsonify
from detector import cal_score,parser_input
from flask import render_template

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
    return render_template("index.html")
if __name__ == "__main__":
    app.run(debug=False)