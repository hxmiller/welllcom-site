from flask import Flask, render_template

app = Flask(__name__)

@app.get("/")
def home():
    return render_template("index.html")

@app.get("/login")
def login():
    return render_template("login.html")

# Nice-to-have: Heroku health check / keep-alive pings
@app.get("/health")
def health():
    return {"ok": True}

if __name__ == "__main__":
    # Local dev only
    app.run(host="0.0.0.0", port=5000, debug=True)
