# app/main.py
from fastapi import FastAPI
import json
from pathlib import Path
import pandas as pd
from typing import Optional, Dict, Any

app = FastAPI()

# 경로
DATA_DIR = Path(__file__).resolve().parent / "data"
RULES_PATH = DATA_DIR / "rules.json"
USERS_DIR = DATA_DIR / "users"

# RULES 로드 (코랩 RULES를 json.dump 한 것)
with open(RULES_PATH, "r", encoding="utf-8") as f:
    RULES = json.load(f)
# JSON 특성상 ordinal_inv.mapping 키가 문자열이므로 정수로 복원
for feat, spec in RULES.get("features", {}).items():
    if spec.get("type") == "ordinal_inv" and "mapping" in spec:
        spec["mapping"] = {int(k): int(v) for k, v in spec["mapping"].items()}

# 전처리


def preprocess_df(
        df: pd.DataFrame, *, event_ts_col: Optional[str] = None, snapshot_ts: Optional[pd.Timestamp] = None,) -> pd.DataFrame:
    out = df.copy()

    # 1) 드롭
    for c in ["department", "job_title", "os_name", "user_id", "device_id", "user_agent_fingerprint", "src_ip", "pdp_pep_decision"]:
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
            ref = prev_ts.max() if prev_ts.notna().any(
            ) else pd.Timestamp.utcnow().tz_localize("UTC")
            days = (ref - prev_ts).dt.total_seconds() / 86400.0
        out["days_since_prev_success"] = days.astype("float32")
        out.drop(columns=["previous_success_login_ts"], inplace=True)

    # 3) os_version → os_version_major
    if "os_version" in out.columns:
        maj = out["os_version"].astype(str).str.extract(r"^(\d+)").iloc[:, 0]
        out["os_version_major"] = pd.to_numeric(
            maj, errors="coerce").fillna(-1).astype("int16")
        out.drop(columns=["os_version"], inplace=True)

    # 4) *_info / *_context / user_role / locale_lang / access_action / access_resource_name / device_owner → OHE
    ohe_cols = [c for c in out.columns if c.endswith(
        "_info") or c.endswith("_context")]
    if ohe_cols:
        out = pd.get_dummies(out, columns=ohe_cols)
        new_dummy_cols = [c for c in out.columns if any(
            c.startswith(base + "_") for base in ohe_cols)]
        if new_dummy_cols:
            out[new_dummy_cols] = out[new_dummy_cols].astype("int8")
    if "user_role" in out.columns:
        out = pd.get_dummies(out, columns=["user_role"])
        cols = [c for c in out.columns if c.startswith("user_role_")]
        if cols:
            out[cols] = out[cols].astype("int8")
    if "locale_lang" in out.columns:
        out = pd.get_dummies(out, columns=["locale_lang"])
        cols = [c for c in out.columns if c.startswith("locale_lang_")]
        if cols:
            out[cols] = out[cols].astype("int8")
    if "access_action" in out.columns:
        out = pd.get_dummies(out, columns=["access_action"])
        cols = [c for c in out.columns if c.startswith("access_action_")]
        if cols:
            out[cols] = out[cols].astype("int8")
    if "access_resource_name" in out.columns:
        out = pd.get_dummies(out, columns=["access_resource_name"])
        cols = [c for c in out.columns if c.startswith(
            "access_resource_name_")]
        if cols:
            out[cols] = out[cols].astype("int8")
    if "device_owner" in out.columns:
        out = pd.get_dummies(out, columns=["device_owner"])
        cols = [c for c in out.columns if c.startswith("device_owner_")]
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

    # 8) geo_is_allowed
    if "geo_country" in out.columns:
        allowed = {"KR", "US"}
        out["geo_is_allowed"] = out["geo_country"].isin(allowed).astype("int8")
        out.drop(columns=["geo_country"], inplace=True)

    # 9) network_type → net_trust_level
    if "network_type" in out.columns:
        trust_map = {"office_lan": 0, "vpn": 1, "home_wifi": 2,
                     "mobile_hotspot": 3, "public_wifi": 4}
        nt = out["network_type"].astype(str).str.lower().str.strip()
        out["net_trust_level"] = nt.map(trust_map).fillna(2).astype("int8")
        out.drop(columns=["network_type"], inplace=True)

    return out

# RULES 점수 계산


def _score_feature_value(val, rule, neutral=0):
    import pandas as pd
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
        start, end, tol = int(rule.get("start", 9)), int(
            rule.get("end", 18)), int(rule.get("tolerance", 2))
        in_score, out_score = rule.get(
            "in_score", neutral), rule.get("out_score", neutral)
        h = int(val)
        return in_score if (start - tol) <= h <= (end + tol) else out_score
    if t == "ordinal_inv":
        return rule.get("mapping", {}).get(int(val), neutral)
    return neutral


def trust_scores_RULES(df: pd.DataFrame, RULES: dict, neutral=0):
    feats, groups, weights = RULES.get("features", {}), RULES.get(
        "groups", {}), RULES.get("weights", {})
    out = df.copy()
    out["trust_score"] = 0.0
    total_w = sum(weights.values()) or 1
    for gname, gcols in groups.items():
        valid = [c for c in gcols if c in df.columns and c in feats]
        if not valid:
            continue
        group_mean = pd.Series([0.0]*len(df), index=df.index)
        for col in valid:
            rule = feats[col]
            group_mean += df[col].apply(
                lambda v: _score_feature_value(v, rule, neutral))
        group_mean /= len(valid)
        out["trust_score"] += group_mean * (weights.get(gname, 0)/total_w)
    out["trust_score"] = out["trust_score"].clip(0, 100).round(1)
    return out

# 유저 JSON 로드 & 점수 응답


def load_user_json(username: str) -> Optional[Dict[str, Any]]:
    path = USERS_DIR / f"{username}.json"
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


@app.get("/score/{username}")
def get_user_score(username: str):
    rec = load_user_json(username)
    if not rec:
        return {"username": username, "score": 50}
    df = pd.DataFrame([rec])
    df_proc = preprocess_df(df)
    df_scored = trust_scores_RULES(df_proc, RULES)
    score = int(round(float(df_scored["trust_score"].iloc[0])))
    return {"username": username, "score": score}
