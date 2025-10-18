from fastapi import FastAPI, Query
from typing import Optional, Dict, Any
import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime


app = FastAPI(title="UEM Score (Colab-identical pipeline)", version="1.0.0")

# ---------- Paths / Settings ----------
BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
USERS = os.path.join(DATA, "users")
RULES_PATH = os.path.join(DATA, "rules.json")
MODEL_PATH = os.path.join(DATA, "zt_xgb_model.pkl")

DEFAULT_SCORE = int(os.getenv("DEFAULT_SCORE", "50"))
RETURN_MODE = os.getenv("RETURN_MODE", "blend").lower()

# 룰만 사용하겠다 1.0, 모델만 사용하겠다. 0.0
BLEND_ALPHA = float(os.getenv("BLEND_ALPHA", "1.0"))

# ---------- Load RULES (JSON) ----------
try:
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        RULES = json.load(f)
except FileNotFoundError:
    print(f"Error: RULES file not found at {RULES_PATH}. Using empty rules.")
    RULES = {"features": {}, "groups": {}, "weights": {}}


for feat, spec in RULES.get("features", {}).items():
    if spec.get("type") == "ordinal_inv" and "mapping" in spec:
        spec["mapping"] = {int(k): int(v) for k, v in spec["mapping"].items()}

# ---------- Load PKL (model + feature_columns) ----------
try:
    artifact = joblib.load(MODEL_PATH)
    MODEL = artifact["model"]
    FEATURE_COLUMNS = artifact["feature_columns"]
except FileNotFoundError:
    print(f"Error: Model file not found at {MODEL_PATH}. Using dummy model.")

    class DummyModel:
        def predict_proba(self, X): return np.array(
            [[0.0, 0.0, 1.0, 0.0, 0.0]])

        def predict(self, X): return np.array([2])
    MODEL = DummyModel()
    # 주의: 실제 환경에서는 FEATURE_COLUMNS가 로딩되어야 합니다.
    FEATURE_COLUMNS = []


# ===================== 1. Data Preprocessing (Final) =====================

def preprocess_df(
    df: pd.DataFrame,
    *,
    event_ts_col: Optional[str] = None,
    snapshot_ts: Optional[pd.Timestamp] = None,
) -> pd.DataFrame:
    out = df.copy()

    # 1) 드롭
    for c in ["department", "job_title", "os_name", "user_id", "device_id",
              "user_agent_fingerprint", "src_ip", "pdp_pep_decision"]:
        if c in out.columns:
            out.drop(columns=c, inplace=True)

    # 2) previous_success_login_ts → days_since_prev_success
    if "previous_success_login_ts" in out.columns:
        prev_ts = pd.to_datetime(
            out["previous_success_login_ts"], utc=True, errors="coerce")
        if event_ts_col and event_ts_col in out.columns:
            evt_ts = pd.to_datetime(
                out[event_ts_col], utc=True, errors="coerce")
            days = (evt_ts - prev_ts).dt.total_seconds() / 86400.0
        else:
            # 현재 시각(UTC)을 기준 시점으로 사용
            ref = (snapshot_ts.tz_convert("UTC") if isinstance(snapshot_ts, pd.Timestamp)
                   else (prev_ts.max() if prev_ts.notna().any()
                         else pd.Timestamp.utcnow().tz_localize("UTC")))
            days = (ref - prev_ts).dt.total_seconds() / 86400.0
        out["days_since_prev_success"] = days.astype("float32")
        out.drop(columns=["previous_success_login_ts"], inplace=True)

    # 3) os_version → os_version_major
    if "os_version" in out.columns:
        maj = out["os_version"].astype(str).str.extract(r"^(\d+)").iloc[:, 0]
        out["os_version_major"] = pd.to_numeric(
            maj, errors="coerce").fillna(-1).astype("int16")
        out.drop(columns=["os_version"], inplace=True)

    # 4) OHE 처리
    ohe_cols = [c for c in out.columns if c.endswith(
        "_info") or c.endswith("_context")]
    if ohe_cols:
        out = pd.get_dummies(out, columns=ohe_cols)
        new_dummy_cols = [c for c in out.columns if any(
            c.startswith(base + "_") for base in ohe_cols)]
        if new_dummy_cols:
            out[new_dummy_cols] = out[new_dummy_cols].astype("int8")

    for col_name in ["user_role", "locale_lang", "access_action", "access_resource_name", "device_owner"]:
        if col_name in out.columns:
            out = pd.get_dummies(out, columns=[col_name])
            cols = [c for c in out.columns if c.startswith(col_name + "_")]
            if cols:
                out[cols] = out[cols].astype("int8")

    # 5) proxy_vpn_tor → vpn_signal
    if "proxy_vpn_tor" in out.columns:
        out["vpn_signal"] = out["proxy_vpn_tor"].astype(
            str).str.lower().eq("vpn").astype("int8")
        out.drop(columns=["proxy_vpn_tor"], inplace=True)

    # 6) access_resource_sensitivity → ordinal
    if "access_resource_sensitivity" in out.columns:
        sens_map = {"low": 0, "medium": 1, "high": 2}
        out["access_resource_sensitivity_ord"] = (
            out["access_resource_sensitivity"].astype(str).str.lower()
            .map(sens_map).fillna(-1).astype("int8")
        )
        out.drop(columns=["access_resource_sensitivity"], inplace=True)

    # 7) boolean → 0/1
    for b in ["mfa_used", "disk_encrypt", "impossible_travel"]:
        if b in out.columns:
            out[b] = out[b].astype("Int8").fillna(0).astype("int8")

    # 8) geo_country → geo_is_allowed
    if "geo_country" in out.columns:
        allowed = {"KR", "US"}
        out["geo_is_allowed"] = out["geo_country"].isin(allowed).astype("int8")
        out.drop(columns=["geo_country"], inplace=True)

    # 9) network_type → net_trust_level (코랩 원형 5개 값만 인식)
    if "network_type" in out.columns:
        trust_map = {
            "office_lan": 0, "vpn": 1, "home_wifi": 2, "mobile_hotspot": 3, "public_wifi": 4
        }
        nt = out["network_type"].astype(str).str.lower().str.strip()
        out["net_trust_level"] = nt.map(trust_map).fillna(2).astype("int8")
        out.drop(columns=["network_type"], inplace=True)

    # ★★★ OHE/Boolean 피처 보강: 룰 계산 일관성 확보 (94점 문제 해결책) ★★★
    rule_features_needed = set(
        [f for gcols in RULES.get("groups", {}).values() for f in gcols]
    )

    for feature in rule_features_needed:
        if feature not in out.columns:
            out[feature] = 0
            if RULES["features"].get(feature, {}).get("type") == "boolean" or any(feature.startswith(p + "_") for p in ["auth_context", "user_info", "user_role", "locale_lang", "location_info", "behavior_context", "access_resource_name"]):
                out[feature] = out[feature].astype("int8")

    return out


# ===================== 2. Rule Scoring (Final) =====================

def _score_feature_value(val, rule, neutral=0):
    t = rule.get("type")
    if pd.isna(val):
        return neutral
    if t == "boolean":
        return rule.get("true_score", neutral) if int(val) == 1 else rule.get("false_score", neutral)
    if t == "bin":
        bins, scores = rule.get("bins", []), rule.get("scores", [])
        for i in range(len(bins) - 1):
            if bins[i] <= float(val) < bins[i + 1]:
                return scores[i]
        return scores[-1] if scores else neutral
    if t == "band_zero":
        return rule.get("good", neutral) if abs(int(val)) == 0 else rule.get("bad", neutral)
    if t == "workhour_band":
        s, e, tol = int(rule.get("start", 9)), int(
            rule.get("end", 18)), int(rule.get("tolerance", 2))
        in_s, out_s = rule.get("in_score", neutral), rule.get(
            "out_score", neutral)
        h = int(val)
        return in_s if (s - tol) <= h <= (e + tol) else out_s
    if t == "ordinal_inv":
        return rule.get("mapping", {}).get(int(val), neutral)
    return neutral


def trust_scores_RULES(df: pd.DataFrame, RULES: dict, neutral=0) -> pd.DataFrame:
    """최종 룰 점수 계산 함수 (0-100 스케일)"""
    feats, groups, weights = RULES["features"], RULES["groups"], RULES["weights"]
    out = df.copy()
    out["trust_score"] = 0.0
    total = sum(weights.values()) or 1
    for gname, gcols in groups.items():
        cols = [c for c in gcols if c in df.columns and c in feats]
        if not cols:
            continue
        gmean = pd.Series([0.0]*len(df), index=df.index)
        for c in cols:
            rule = feats[c]
            gmean += df[c].apply(lambda v: _score_feature_value(v,
                                 rule, neutral))
        gmean /= len(cols)
        out["trust_score"] += gmean * (weights.get(gname, 0)/total)
    # 0->100 스케일링 로직 (코랩과 통일)
    out["trust_score"] = (out["trust_score"] * 10).clip(0, 100).round(1)
    return out


# ===================== 3. Model Scoring & 4. Utility / API =====================

def vectorize(dfp: pd.DataFrame, feats: list[str]) -> np.ndarray:
    X = dfp.copy()
    for c in feats:
        if c not in X.columns:
            X[c] = 0
    X = X[feats]
    for c in X.columns:
        if X[c].dtype == "O":
            X[c] = pd.to_numeric(X[c], errors="coerce")
    return X.fillna(0).to_numpy(dtype=float)


def ml_proba_to_score(proba: np.ndarray) -> int:
    anchors = np.array([10, 30, 50, 70, 90], dtype=float)
    return int(max(0, min(100, round(float(np.dot(proba, anchors))))))


def load_user_json(username: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(USERS, f"{username}.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


@app.get("/score/{username}")
def get_user_score(username: str, mode: Optional[str] = Query(None, description="rule|model|blend (optional override)")):
    rec = load_user_json(username)
    if not rec:
        return {"username": username, "score": DEFAULT_SCORE}

    df_raw = pd.DataFrame([rec])

    # 1. RULE score 계산
    # user1의 75점 문제를 해결하려면, 이 곳에 snapshot_ts를 고정 주입해야 합니다.
    # 예시: snapshot_ts=pd.to_datetime('2025-10-10T12:00:00Z', utc=True)
    dfp = preprocess_df(df_raw.copy())
    rule_df = trust_scores_RULES(dfp, RULES)
    rule_score = float(rule_df["trust_score"].iloc[0])

    # 2. MODEL score 계산
    X = vectorize(dfp.copy(), FEATURE_COLUMNS)

    if hasattr(MODEL, "predict_proba") and len(FEATURE_COLUMNS) > 0 and X.shape[1] == len(FEATURE_COLUMNS):
        proba = MODEL.predict_proba(X)[0]
        ml_score = ml_proba_to_score(proba)
    else:
        ml_score = 50

    # 3. 최종 점수 결정
    m = (mode or RETURN_MODE).lower()
    if m == "rule":
        final = int(round(rule_score))
    elif m == "model":
        final = int(round(ml_score))
    else:  # blend
        final = int(round(BLEND_ALPHA * rule_score +
                          (1.0 - BLEND_ALPHA) * ml_score))

    return {"username": username, "score": final}
