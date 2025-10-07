import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from xgboost import XGBClassifier
import matplotlib.pyplot as plt
from sklearn.utils import shuffle
import re, ipaddress
from typing import Tuple, Optional
from sklearn.model_selection import train_test_split

from google.colab import drive
drive.mount('/content/gdrive')
colab_path = "/content/gdrive/MyDrive/KISIA_ZT/Data/"

df_normal = pd.read_csv(colab_path + 'train_normal.csv')
df_anormalous = pd.read_csv(colab_path+ 'val_anomalous.csv')

RULES = { #수정필요
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

df_normal["label"]=0
df_anormalous["label"]=1

df_mix = pd.concat([df_normal, df_anormalous])
df_mix = df_mix.sample(frac=1, random_state=42).reset_index(drop=True)

df_train, df_test = train_test_split(df_mix, test_size= 0.2, stratify=df_mix["label"],random_state=42)

def preprocess_df(
    df: pd.DataFrame,
    *,
    event_ts_col: Optional[str] = None,
    snapshot_ts: Optional[pd.Timestamp] = None,
) -> Tuple[pd.DataFrame, list, list]:
    out = df.copy()

    # 1) 드롭
    for c in ["os_name", "user_id", "device_id", "user_agent_fingerprint", "trust_score", "src_ip", "pdp_pep_decision"]:
        if c in out.columns:
            out.drop(columns=c, inplace=True)

    # 2) previous_success_login_ts → days_since_prev_success 로그인 이후 지난 시간으로 변경
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

    # 3) os_version
    if "os_version" in out.columns:
        maj = out["os_version"].astype(str).str.extract(r"^(\d+)").iloc[:, 0]
        out["os_version_major"] = pd.to_numeric(maj, errors="coerce").fillna(-1).astype("int16")
        out.drop(columns=["os_version"], inplace=True)

    # 4) _info / _context/user_role/locale_lang/access_action/access_resource_name/device_owner OHE
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



    # 5) 'vpn'이면 1, 그 외 0
    out["vpn_signal"] = out["proxy_vpn_tor"].astype(str).str.lower().eq("vpn").astype("int8")

    # 6) access_resource_sensitivity → low = 0, medium = 1, high = 2
    if "access_resource_sensitivity" in out.columns:
        sens_map = {"low": 0, "medium": 1,"high":2}
        out["access_resource_sensitivity_ord"] = (
            out["access_resource_sensitivity"].astype(str).str.lower()
              .map(sens_map).fillna(-1).astype("int8")
        )
        out.drop(columns=["access_resource_sensitivity"], inplace=True)

    # 7) boolean → 0/1
    for b in ["mfa_used", "disk_encrypt", "impossible_travel"]:
        if b in out.columns:
            out[b] = out[b].astype("Int8").fillna(0).astype("int8")
    # 8) 허용국 접속=1 / 허용국 X = 0
    allowed = {"KR", "US"}  #허용국가
    out["geo_is_allowed"] = out["geo_country"].isin(allowed).astype("int8")
    out.drop(columns=["geo_country"], inplace=True)
    # 9) 기타
    # "network_type" 공공망/사내망
    # "department" 부서별 점수?
    # "job_title" 직급 별 신뢰도


    return out

df_train_processed = preprocess_df(df_train)
df_train_processed = df_train_processed.drop(columns=["network_type","proxy_vpn_tor","job_title","department"])
df_test_processed = preprocess_df(df_test)
df_test_processed = df_test_processed.drop(columns=["network_type","proxy_vpn_tor","job_title","department"])

X_train = df_train_processed.drop(columns=["label"])
y_train = df_train_processed["label"]

X_test = df_test_processed.drop(columns=["label"])
y_test = df_test_processed["label"]


model = XGBClassifier(
    n_estimators=300,
    learning_rate=0.1,
    max_depth=6,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
print(f"F1 Score : {f1_score(y_test, y_pred):.4f}")
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("\nClassification:")
print(classification_report(y_test, y_pred))
