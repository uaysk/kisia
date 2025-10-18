import os
import json
import pandas as pd
from app import preprocess_df, trust_scores_RULES, RULES

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS = os.path.join(BASE, "data", "users")


def check(username):
    path = os.path.join(USERS, f"{username}.json")
    rec = json.load(open(path, "r", encoding="utf-8"))
    df = pd.DataFrame([rec])
    dfp = preprocess_df(df.copy())
    scored = trust_scores_RULES(dfp, RULES)
    print(username, "=>", float(scored["trust_score"].iloc[0]))


if __name__ == "__main__":
    check("user1")
    check("user2")
