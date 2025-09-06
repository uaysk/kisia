from fastapi import FastAPI

app = FastAPI()

# Hardcoded user security scores
user_scores = {
    "user_a": 100,
    "user_b": 70,
    "testuser": 90,
}

@app.get("/score/{username}")
def get_user_score(username: str):
    """Returns the security score for a given username."""
    return {"username": username, "score": user_scores.get(username, 50)} # Default score 50 if user not found
