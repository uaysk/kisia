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
import joblib
from sklearn.model_selection import GridSearchCV

from google.colab import drive
drive.mount('/content/gdrive')
colab_path = "/content/gdrive/MyDrive/KISIA_ZT/Data/"

df_normal = pd.read_csv(colab_path + 'train_normal.csv')
df_anormalous = pd.read_csv(colab_path+ 'val_anomalous.csv')

def preprocess_df(
    df: pd.DataFrame,
    *,
    event_ts_col: Optional[str] = None,
    snapshot_ts: Optional[pd.Timestamp] = None,
) -> Tuple[pd.DataFrame, list, list]:
    out = df.copy()

    # 1) 드롭
    for c in ["department","job_title","os_name", "user_id", "device_id", "user_agent_fingerprint", "trust_score", "src_ip", "pdp_pep_decision"]:
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

    # 5) proxy_vpn_tor → vpn이면 1, 아니면 0 (bool 처리)
    if "proxy_vpn_tor" in out.columns:
        out["vpn_signal"] = (
            out["proxy_vpn_tor"].astype(str).str.lower().eq("vpn").astype("int8")
        )
        out.drop(columns=["proxy_vpn_tor"], inplace=True)

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
    # 9) netowrk_type 내부망:0 / vpn:1/ home_wifi:2 / mobile_hotspot :3/ public)wifi :4 (숫자가 낮으면 안전)
    if "network_type" in out.columns:
      trust_map = {
          "office_lan": 0,
         "vpn": 1,
         "home_wifi": 2,
         "mobile_hotspot": 3,
         "public_wifi": 4
      }
      nt = out["network_type"].astype(str).str.lower().str.strip()

      out["net_trust_level"] = (
          nt.map(trust_map)
            .fillna(2)
            .astype("int8")
      )
      out.drop(columns=["network_type"], inplace=True)

    return out



df_normal["label"]=0
df_anormalous["label"]=1

df_normal.dtypes

df_mix = pd.concat([df_normal, df_anormalous])
df_mix = df_mix.sample(frac=1, random_state=42).reset_index(drop=True)

df_train, df_test = train_test_split(df_mix, test_size= 0.2, stratify=df_mix["label"],random_state=42)

def split_datasets_by_trust_score(df_train, df_test, step=10):
    bins = list(range(0, 101, step))

    for dataset_name, df in [("train", df_train), ("test", df_test)]:
        for i in range(len(bins)-1):
            low, high = bins[i], bins[i+1]
            mask = (df["trust_score"] >= low) & (df["trust_score"] < high)
            globals()[f"df_{dataset_name}_{low}_{high}"] = df[mask].copy()
            print(f"Created df_{dataset_name}_{low}_{high} → {mask.sum()} rows")
split_datasets_by_trust_score(df_train, df_test)

def preprocess_df(
    df: pd.DataFrame,
    *,
    event_ts_col: Optional[str] = None,
    snapshot_ts: Optional[pd.Timestamp] = None,
) -> Tuple[pd.DataFrame, list, list]:
    out = df.copy()

    # 1) 드롭
    for c in ["department","job_title","os_name", "user_id", "device_id", "user_agent_fingerprint", "trust_score", "src_ip", "pdp_pep_decision"]:
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


    # 5) proxy_vpn_tor → vpn이면 1, 아니면 0 (bool 처리)
    if "proxy_vpn_tor" in out.columns:
        out["vpn_signal"] = (
            out["proxy_vpn_tor"].astype(str).str.lower().eq("vpn").astype("int8")
        )
        out.drop(columns=["proxy_vpn_tor"], inplace=True)


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
    # 9) netowrk_type 내부망:0 / vpn:1/ home_wifi:2 / mobile_hotspot :3/ public)wifi :4 (숫자가 낮으면 안전)
    if "network_type" in out.columns:
      trust_map = {
          "office_lan": 0,
         "vpn": 1,
         "home_wifi": 2,
         "mobile_hotspot": 3,
         "public_wifi": 4
      }
      nt = out["network_type"].astype(str).str.lower().str.strip()

      out["net_trust_level"] = (
          nt.map(trust_map)
            .fillna(2)
            .astype("int8")
      )
      out.drop(columns=["network_type"], inplace=True)


    return out

df_train_processed = preprocess_df(df_train)
df_test_processed = preprocess_df(df_test)

X_train = df_train_processed.drop(columns=["label"])
y_train = df_train_processed["label"]

X_test = df_test_processed.drop(columns=["label"])
y_test = df_test_processed["label"]


model = XGBClassifier(
    n_estimators=300,
    learning_rate=0.05,
    max_depth=3,
    subsample=0.6,
    colsample_bytree=0.6,
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

importances = model.feature_importances_
feature_names = X_train.columns
importance_df = pd.DataFrame({
    "Feature": feature_names,
    "Importance": importances
}).sort_values(by="Importance", ascending=False)

print(importance_df.head(15))

def _score_feature_value(val, rule, neutral=0):
    t = rule.get("type")
    if pd.isna(val):
        return neutral

    if t == "boolean":
        true_s  = rule.get("true_score", neutral)
        false_s = rule.get("false_score", neutral)
        return true_s if int(val) == 1 else false_s

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
        start     = int(rule.get("start", 9))
        end       = int(rule.get("end", 18))
        tol       = int(rule.get("tolerance", 2))
        in_score  = rule.get("in_score", neutral)
        out_score = rule.get("out_score", neutral)
        h = int(val)
        return in_score if (start - tol) <= h <= (end + tol) else out_score

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

df_train_scored = trust_scores_RULES(df_train_processed, RULES)
df_test_scored  = trust_scores_RULES(df_test_processed, RULES)

artifact = {
    "model": model,
    "feature_columns": list(X_train.columns),
    "created_at": str(pd.Timestamp.utcnow()),
    "params": model.get_params()
}

joblib.dump(artifact, "zt_xgb_model.pkl")
