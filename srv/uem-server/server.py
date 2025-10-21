import logging
import os
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib


logger = logging.getLogger(__name__)

RULES= {
    "features": {
        "mfa_used": {"type": "boolean", "true_score": 10, "false_score": 0},
        "failed_attempts_recent": {"type": "bin", "bins": [0, 1, 3, 5, 10**9], "scores": [10, 8, 5, 0]},
        "days_since_prev_success": {"type": "bin", "bins": [0, 1, 7, 30, 10**9], "scores": [10, 8, 5, 0]},
        "auth_context_MFA": {"type": "boolean", "true_score": 10, "false_score": 0},
        "auth_context_비밀번호만": {"type": "boolean", "true_score": 0, "false_score": 5},

        "patch_age_days": {"type": "bin", "bins": [0, 30, 90, 180, 10**9], "scores": [10, 8, 5, 0]},
        "disk_encrypt": {"type": "boolean", "true_score": 10, "false_score": 0},
        "os_version_major": {"type": "bin", "bins": [0, 6, 7, 10**9], "scores": [0, 5, 10]},
        "software_info_EDR/MDM 정책 준수": {"type": "boolean", "true_score": 10, "false_score": 0},
        "software_info_컨테이너/앱 격리": {"type": "boolean", "true_score": 10, "false_score": 0},
        "device_owner_company": {"type": "boolean", "true_score": 10, "false_score": 0},
        "device_owner_personal": {"type": "boolean", "true_score": 0, "false_score": 5},

        "impossible_travel": {"type": "boolean", "true_score": 0, "false_score": 10},
        "vpn_signal": {"type": "boolean", "true_score": 5, "false_score": 10},
        "network_context_VPN": {"type": "boolean", "true_score": 8, "false_score": 5},
        "network_context_가정/모바일망": {"type": "boolean", "true_score": 5, "false_score": 8},
        "network_context_공용망": {"type": "boolean", "true_score": 0, "false_score": 10},
        "geo_is_allowed": {"type": "boolean", "true_score": 10, "false_score": 0},
        "net_trust_level": {
            "type": "ordinal_inv",
            "mapping": { -1: 0, 0: 10, 1: 8, 2: 6, 3: 3, 4: 0 }
        },

        "tz_offset_minutes": {"type": "band_zero", "good": 10, "bad": 0},
        "login_hour_local": {"type": "workhour_band", "start": 9, "end": 18, "tolerance": 2, "in_score": 10, "out_score": 3},
        "time_info_근무시간": {"type": "boolean", "true_score": 10, "false_score": 5},
        "time_info_야간": {"type": "boolean", "true_score": 3, "false_score": 10},

        "behavior_context_대량 전송": {"type": "boolean", "true_score": 0, "false_score": 10},
        "behavior_context_일반 조회/업로드": {"type": "boolean", "true_score": 10, "false_score": 5},

        "access_action_download": {"type": "boolean", "true_score": 3, "false_score": 8},
        "access_action_upload": {"type": "boolean", "true_score": 5, "false_score": 8},
        "access_action_read": {"type": "boolean", "true_score": 10, "false_score": 5},

        "access_resource_sensitivity_ord": {
            "type": "ordinal_inv",
            "mapping": { -1: 0, 0: 3, 1: 6, 2: 10 }
        },

        "access_resource_name_crm": {"type": "boolean", "true_score": 8, "false_score": 5},
        "access_resource_name_doc_repo": {"type": "boolean", "true_score": 6, "false_score": 5},
        "access_resource_name_hr_db": {"type": "boolean", "true_score": 10, "false_score": 5},
        "access_resource_name_internal_intra_db": {"type": "boolean", "true_score": 8, "false_score": 5},
        "access_resource_name_intra": {"type": "boolean", "true_score": 5, "false_score": 5},
        "access_resource_name_mail": {"type": "boolean", "true_score": 5, "false_score": 5},
        "access_resource_name_project_repo": {"type": "boolean", "true_score": 6, "false_score": 5},

        "user_role_employee": {"type": "boolean", "true_score": 10, "false_score": 5},
        "user_role_guest": {"type": "boolean", "true_score": 5, "false_score": 10},

        "user_info_정규직": {"type": "boolean", "true_score": 10, "false_score": 5},
        "user_info_외부 게스트": {"type": "boolean", "true_score": 5, "false_score": 10},

        "locale_lang_ko-KR": {"type": "boolean", "true_score": 10, "false_score": 5},
        "locale_lang_en-US": {"type": "boolean", "true_score": 8, "false_score": 5},
        "locale_lang_ja-JP": {"type": "boolean", "true_score": 5, "false_score": 8},

        "location_info_국내": {"type": "boolean", "true_score": 10, "false_score": 5},
        "location_info_해외 허용국": {"type": "boolean", "true_score": 8, "false_score": 5},
        "location_info_해외 금지국": {"type": "boolean", "true_score": 0, "false_score": 10},
    },

    "groups": {
        "identity": [
            "mfa_used", "failed_attempts_recent", "days_since_prev_success",
            "auth_context_MFA", "auth_context_비밀번호만",
            "user_info_정규직", "user_info_외부 게스트",
            "user_role_employee", "user_role_guest"
        ],
        "device": [
            "patch_age_days", "disk_encrypt", "os_version_major",
            "software_info_EDR/MDM 정책 준수", "software_info_컨테이너/앱 격리",
            "device_owner_company", "device_owner_personal"
        ],
        "network": [
            "impossible_travel", "vpn_signal", "network_context_VPN",
            "network_context_가정/모바일망", "network_context_공용망",
            "geo_is_allowed", "net_trust_level"
        ],
        "time_env": [
            "tz_offset_minutes", "login_hour_local",
            "time_info_근무시간", "time_info_야간"
        ],
        "behavior": [
            "behavior_context_대량 전송", "behavior_context_일반 조회/업로드",
            "access_action_download", "access_action_upload", "access_action_read",
            "access_resource_sensitivity_ord",
            "access_resource_name_crm", "access_resource_name_doc_repo",
            "access_resource_name_hr_db", "access_resource_name_internal_intra_db",
            "access_resource_name_intra", "access_resource_name_mail",
            "access_resource_name_project_repo"
        ],
        "locale_location": [
            "locale_lang_ko-KR", "locale_lang_en-US", "locale_lang_ja-JP",
            "location_info_국내", "location_info_해외 허용국", "location_info_해외 금지국"
        ],
    },

    "weights": { "identity": 20, "device": 20, "network": 20, "time_env": 15, "behavior": 15, "locale_location": 10 }
}

def preprocess_df(
    df: pd.DataFrame,
    *,
    event_ts_col: Optional[str] = None,
    snapshot_ts: Optional[pd.Timestamp] = None,
) -> pd.DataFrame:
    out = df.copy()

    for c in ["department","job_title","os_name", "user_id", "device_id", "user_agent_fingerprint", "src_ip", "pdp_pep_decision"]:
        if c in out.columns:
            out.drop(columns=c, inplace=True)

    if "previous_success_login_ts" in out.columns:
        prev_ts = pd.to_datetime(out["previous_success_login_ts"], utc=True, errors="coerce")
        if event_ts_col and event_ts_col in out.columns:
            evt_ts = pd.to_datetime(out[event_ts_col], utc=True, errors="coerce")
            days = (evt_ts - prev_ts).dt.total_seconds() / 86400.0
        else:
            ref = (snapshot_ts.tz_convert("UTC") if isinstance(snapshot_ts, pd.Timestamp)
                   else (prev_ts.max() if prev_ts.notna().any()
                         else pd.Timestamp.utcnow().tz_localize("UTC")))
            days = (ref - prev_ts).dt.total_seconds() / 86400.0
        out["days_since_prev_success"] = days.astype("float32")
        out.drop(columns=["previous_success_login_ts"], inplace=True)

    if "os_version" in out.columns:
        maj = out["os_version"].astype(str).str.extract(r"^(\d+)").iloc[:, 0]
        out["os_version_major"] = pd.to_numeric(maj, errors="coerce").fillna(-1).astype("int16")
        out.drop(columns=["os_version"], inplace=True)

    ohe_cols = [c for c in out.columns if c.endswith("_info") or c.endswith("_context")]
    if ohe_cols:
        out = pd.get_dummies(out, columns=ohe_cols)
        new_dummy_cols = [c for c in out.columns if any(c.startswith(base + "_") for base in ohe_cols)]
        if new_dummy_cols:
            out[new_dummy_cols] = out[new_dummy_cols].astype("int8")
    if "user_role" in out.columns:
        out = pd.get_dummies(out, columns=["user_role"])
        new_cols = [c for c in out.columns if c.startswith("user_role_")]
        out[new_cols] = out[new_cols].astype("int8")
    if "locale_lang" in out.columns:
        out = pd.get_dummies(out, columns=["locale_lang"])
        new_cols = [c for c in out.columns if c.startswith("locale_lang_")]
        out[new_cols] = out[new_cols].astype("int8")
    if "access_action" in out.columns:
        out = pd.get_dummies(out, columns=["access_action"])
        new_cols = [c for c in out.columns if c.startswith("access_action_")]
        out[new_cols] = out[new_cols].astype("int8")
    if "access_resource_name" in out.columns:
        out = pd.get_dummies(out, columns=["access_resource_name"])
        new_cols = [c for c in out.columns if c.startswith("access_resource_name_")]
        out[new_cols] = out[new_cols].astype("int8")
    if "device_owner" in out.columns:
        out = pd.get_dummies(out, columns=["device_owner"])
        new_cols = [c for c in out.columns if c.startswith("device_owner_")]
        out[new_cols] = out[new_cols].astype("int8")

    if "proxy_vpn_tor" in out.columns:
        out["vpn_signal"] = (
            out["proxy_vpn_tor"].astype(str).str.lower().eq("vpn").astype("int8")
        )
        out.drop(columns=["proxy_vpn_tor"], inplace=True)

    if "access_resource_sensitivity" in out.columns:
        sens_map = {"low": 0, "medium": 1,"high":2}
        out["access_resource_sensitivity_ord"] = (
            out["access_resource_sensitivity"].astype(str).str.lower()
              .map(sens_map).fillna(-1).astype("int8")
        )
        out.drop(columns=["access_resource_sensitivity"], inplace=True)

    for b in ["mfa_used", "disk_encrypt", "impossible_travel"]:
        if b in out.columns:
            out[b] = out[b].astype("Int8").fillna(0).astype("int8")

    if "geo_country" in out.columns:
        allowed = {"KR", "US"}
        out["geo_is_allowed"] = out["geo_country"].isin(allowed).astype("int8")
        out.drop(columns=["geo_country"], inplace=True)

    if "network_type" in out.columns:
        trust_map = {
            "office_lan": 0, "vpn": 1, "home_wifi": 2, "mobile_hotspot": 3, "public_wifi": 4
        }
        nt = out["network_type"].astype(str).str.lower().str.strip()
        out["net_trust_level"] = (
            nt.map(trust_map).fillna(2).astype("int8")
        )
        out.drop(columns=["network_type"], inplace=True)

    return out

def _score_feature_value(val, rule, neutral=0):
    if pd.isna(val):
        return neutral
    t = rule.get("type")
    if t == "boolean":
        return rule.get("true_score", neutral) if int(val) == 1 else rule.get("false_score", neutral)
    if t == "bin":
        bins   = rule.get("bins", [])
        scores = rule.get("scores", [])
        for i in range(len(bins) - 1):
            if bins[i] <= float(val) < bins[i + 1]:
                return scores[i]
        return scores[-1] if scores else neutral
    if t == "band_zero":
        return rule.get("good", neutral) if abs(int(val)) == 0 else rule.get("bad", neutral)
    if t == "workhour_band":
        start     = int(rule.get("start", 9)); end = int(rule.get("end", 18))
        tol       = int(rule.get("tolerance", 2))
        in_score  = rule.get("in_score", neutral); out_score = rule.get("out_score", neutral)
        h = int(val);  return in_score if (start - tol) <= h <= (end + tol) else out_score
    if t == "ordinal_inv":
        mp = rule.get("mapping", {})
        return mp.get(int(val), neutral)
    return neutral

def trust_scores_RULES(df: pd.DataFrame, RULES: dict, neutral=0):
    feats   = RULES.get("features", {})
    groups  = RULES.get("groups", {})
    weights = RULES.get("weights", {})

    df_out = df.copy()
    df_out["trust_score"] = 0.0
    total_weight = sum(weights.values()) or 1

    for gname, gcols in groups.items():
        valid_cols = [c for c in gcols if c in df.columns and c in feats]
        if not valid_cols:
            continue
        group_mean = pd.Series([0.0] * len(df), index=df.index)
        for col in valid_cols:
            rule = feats[col]
            group_mean += df[col].apply(lambda v: _score_feature_value(v, rule, neutral))
        group_mean /= len(valid_cols)
        weight = weights.get(gname, 0) / total_weight
        df_out["trust_score"] += group_mean * weight

    df_out["trust_score"] = df_out["trust_score"].clip(0, 100).round(1)
    return df_out

TRUST_LABELS = ['매우낮음', '낮음', '보통', '높음', '매우높음']

def scenario_to_dataframe(
    scenario: dict,
    RULES: dict,
    *,
    trust_func,
    preprocess_func,
    return_score: bool = False
):
    data = scenario.copy()
    for k, v in list(data.items()):
        if v in ["", None]:
            data[k] = np.nan
    df = pd.DataFrame([data])
    df_scored = trust_func(df, RULES)
    tscore = float(df_scored["trust_score"].iloc[0]) if "trust_score" in df_scored.columns else np.nan
    df_processed = preprocess_func(df_scored)
    if return_score:
        return df_processed, tscore
    return df_processed

def predict_with_model(df_proc: pd.DataFrame, artifact) -> Dict[str, Any]:
    model = artifact["model"]
    feats = artifact["feature_columns"]
    for c in feats:
        if c not in df_proc.columns:
            df_proc[c] = 0
    X = df_proc[feats].copy()
    for c in X.columns:
        if X[c].dtype == "O":
            X[c] = pd.to_numeric(X[c], errors="coerce")
    X = X.fillna(0)

    proba = model.predict_proba(X)[0]
    pred_id = int(np.argmax(proba))
    label_text = TRUST_LABELS[pred_id] if pred_id < len(TRUST_LABELS) else str(pred_id)
    probs = { (TRUST_LABELS[i] if i < len(TRUST_LABELS) else str(i)): float(proba[i]) for i in range(len(proba)) }

    return {"predicted_id": pred_id, "predicted_label": label_text,
            "confidence": float(proba[pred_id]), "probabilities": probs}

MODEL_PATH = os.environ.get("MODEL_PATH", "zt_xgb_model.pkl")
artifact: Optional[Dict[str, Any]] = None
if MODEL_PATH:
    if os.path.exists(MODEL_PATH):
        artifact = joblib.load(MODEL_PATH)
    else:
        logger.warning("Model artifact not found at %s; model-based predictions disabled.", MODEL_PATH)

app = FastAPI(title="ZT XGBoost Serving API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

class UserScenario(BaseModel):
    username: str
    scenario: Dict[str, Any]


class PredictRequest(UserScenario):
    pass


class PredictBatchRequest(BaseModel):
    scenarios: List[UserScenario]


def _adjust_trust_score(tscore: float) -> float:
    if pd.isna(tscore):
        return float("nan")
    if tscore <= 10:
        return float(np.clip(tscore * 10, 0, 100))
    return float(np.clip(tscore, 0, 100))


def _score_to_label(score: float) -> str:
    if np.isnan(score):
        return "점수없음"
    thresholds = [20, 40, 60, 80]
    idx = sum(score >= th for th in thresholds)
    return TRUST_LABELS[min(idx, len(TRUST_LABELS) - 1)]


def _prepare_scenario(scenario: Dict[str, Any]):
    df_proc, raw_score = scenario_to_dataframe(
        scenario,
        RULES,
        trust_func=trust_scores_RULES,
        preprocess_func=preprocess_df,
        return_score=True,
    )
    adj_score = _adjust_trust_score(raw_score)
    return df_proc, adj_score


DEFAULT_USER_SCORE = 50.0
user_scores_store: Dict[str, float] = {}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/features")
def features():
    if artifact is None:
        raise HTTPException(status_code=503, detail="Model artifact not loaded")
    return {"feature_columns": artifact["feature_columns"]}

@app.get("/version")
def version():
    if artifact is None:
        raise HTTPException(status_code=503, detail="Model artifact not loaded")
    return {
        "created_at": artifact.get("created_at"),
        "model_params": artifact.get("params"),
        "model_path": MODEL_PATH
    }


@app.get("/score/{username}")
def get_user_score(username: str):
    score = user_scores_store.get(username, DEFAULT_USER_SCORE)
    return {"username": username, "score": score}


@app.post("/score")
def score(req: PredictRequest):
    _, adj_score = _prepare_scenario(req.scenario)
    stored_score = DEFAULT_USER_SCORE if np.isnan(adj_score) else adj_score
    user_scores_store[req.username] = stored_score
    return {"username": req.username, "success": True}

@app.post("/predict")
def predict(req: PredictRequest):
    if artifact is None:
        raise HTTPException(status_code=503, detail="Model artifact not loaded")
    df_proc, adj_tscore = _prepare_scenario(req.scenario)
    predict_with_model(df_proc, artifact)
    stored_score = DEFAULT_USER_SCORE if np.isnan(adj_tscore) else adj_tscore
    user_scores_store[req.username] = stored_score
    return {"username": req.username, "success": True}

@app.post("/predict_batch")
def predict_batch(req: PredictBatchRequest):
    if artifact is None:
        raise HTTPException(status_code=503, detail="Model artifact not loaded")
    results = []
    for item in req.scenarios:
        df_proc, adj_tscore = _prepare_scenario(item.scenario)
        predict_with_model(df_proc, artifact)
        stored_score = DEFAULT_USER_SCORE if np.isnan(adj_tscore) else adj_tscore
        user_scores_store[item.username] = stored_score
        results.append({"username": item.username, "success": True})
    return {"results": results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), reload=False)
