import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.gridspec as gridspec
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score

##data_train = pd.read_csv('')

RULES = {
    "features": {
        # Identity
        "mfa_result": {
            "type": "categorical_map",
            "map": {"success": 100, "used_but_fail": 20, "fail": 20, "none": 0}
        },
        # Device
        "patch_age_days": { "type": "bin", "bins": [0, 30, 90, 180, 10**9], "scores": [100, 70, 40, 0] },
        "disk_encrypt":   { "type": "boolean", "true_score": 100, "false_score": 0 },
        "virtual_machine":{ "type": "boolean", "true_score": 60,  "false_score": 100 },
        "os_tamper_flag": { "type": "boolean", "true_score": 0,   "false_score": 100 },
        # Network & Geo
        "network_type": {
            "type": "categorical_map",
            "map": {"company": 100, "home": 60, "public": 30, "hotel": 30, "cafe": 30, "mobile": 60}
        },
        "proxy_vpn_tor":  { "type": "categorical_map", "map": {"none": 100, "vpn": 70, "proxy": 20, "suspicious": 20, "tor": 0} },
        "ip_rep":         { "type": "categorical_map", "map": {"safe": 100, "neutral": 50, "bad": 0} },
        "geo_country":    { "type": "categorical_map", "map": {"KR":100,"US":100,"JP":100,"DE":100,"GB":100,"RU":0,"KP":0,"IR":0} },
        "impossible_travel": { "type": "boolean", "true_score": 0, "false_score": 100 },
        # Environment
        "device_owner":   { "type": "categorical_map", "map": {"company": 100, "personal": 60} },
        "tz_offset_minutes": { "type": "band_zero", "zero_is_good": True, "good": 100, "bad": 80 },
        "locale_lang":    { "type": "passthrough_const", "value": 100 },
        # Behavioral / Session
        "login_hour_local": { "type": "workhour_band", "start": 9, "end": 18, "tolerance": 2, "in_score": 100, "out_score": 50 },
        "failed_attempts_recent": { "type": "bin", "bins": [0,1,4,11,10**9], "scores": [100,80,40,0] },
        "previous_success_login_ts": { "type": "passthrough_const", "value": 100 },
        "user_agent_fingerprint":    { "type": "passthrough_const", "value": 100 },
    },
    "groups": {
        "identity":    ["mfa_result"],
        "device":      ["patch_age_days","disk_encrypt","virtual_machine","os_tamper_flag"],
        "network":     ["network_type","proxy_vpn_tor","ip_rep","geo_country","impossible_travel"],
        "environment": ["device_owner","tz_offset_minutes","locale_lang"],
        "behavioral":  ["login_hour_local","failed_attempts_recent"],
        "session":     ["previous_success_login_ts","user_agent_fingerprint"]
    },
    # 가중치(합=100)
    "weights": {"identity":20,"device":30,"network":20,"behavioral":15,"session":10,"environment":5}
}

def score_one_value(value, rule):
    rtype = rule["type"]

    if rtype == "categorical":
        mapping = rule["map"]
        key = str(value) if value is not None else
        return int(mapping.get(key, mapping.get(key.lower(), 0)))

    if rtype == "boolean":
        true_score = rule.get("true_score", 100)
        false_score = rule.get("false_score", 0)
        val_str = str(value).lower()
        is_true = val_str in ("1","true","yes","y","on")
        return int(true_score if is_true else false_score)

    if rtype == "bin":
        bins = rule["bins"]
        scores = rule["scores"]
        try:
            v = float(value)
        except:
            return 0
        for i in range(len(bins)-1):
            left = bins[i]
            right = bins[i+1]
            if left <= v <= right:
                return int(scores[min(i, len(scores)-1)])
        return int(scores[-1])

    if rtype == "workhour":
        start = rule.get("start", 9)
        end   = rule.get("end", 18)
        tol   = rule.get("tol", 2)
        in_sc = rule.get("in_score", 100)
        out_sc= rule.get("out_score", 50)
        try:
            if isinstance(value, str) and ":" in value:
                hour = int(value.split(":")[0])
            else:
                hour = int(value)
        except:
            return out_sc
        lo = max(0, start - tol)
        hi = min(23, end + tol)
        return int(in_sc if lo <= hour <= hi else out_sc)

    if rtype == "zero_good":
        good = rule.get("good", 100)
        bad  = rule.get("bad", 80)
        try:
            v = float(value)
        except:
            return bad
        return int(good if v == 0 else bad)

    if rtype == "const":
        return int(rule.get("value", 100))

    return 0


def score_dataframe(raw_df, RULES):
    scored = pd.DataFrame(index=raw_df.index)

    for col, rule in RULES["features"].items():
        if col in raw_df.columns:
            scored[col] = raw_df[col].apply(lambda v: score_one_value(v, rule))
        else:
            scored[col] = 0

    group_means = {}
    for gname, cols in RULES["groups"].items():
        valid_cols = [c for c in cols if c in scored.columns]
        if len(valid_cols) == 0:
            group_means[gname] = 0
        else:
            group_means[gname] = scored[valid_cols].mean(axis=1)

    group_df = pd.DataFrame(group_means, index=raw_df.index)

    weighted = 0
    for gname, weight in RULES["weights"].items():
        if gname in group_df.columns:
            weighted = weighted + group_df[gname] * (weight / 100.0)


    result = scored.copy()
    for gname in group_df.columns:
        result[f"{gname}_mean"] = group_df[gname]
    result["weighted_input"] = weighted.clip(0, 100)
    return result


def build_X(scored_df, variant="full"):
    if variant == "compact":
        return scored_df[["weighted_input"]].copy()
    cols = [c for c in scored_df.columns if c.endswith("_mean")] + ["weighted_input"]
    return scored_df[cols].copy()

def fit_isolation_forest(X, contamination=0.05, random_state=42):
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state
    )
    model.fit(X)
    return model
