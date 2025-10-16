import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from xgboost import XGBClassifier
from pandas.api.types import CategoricalDtype
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

df_data = pd.read_csv(colab_path + 'trust_all_100k.csv')

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
) -> Tuple[pd.DataFrame, list, list]:
    out = df.copy()

    # 1) 드롭
    for c in ["department","job_title","os_name", "user_id", "device_id", "user_agent_fingerprint", "src_ip", "pdp_pep_decision"]:
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

    if "trust_score" in out.columns:
      trust_bins = [0, 20, 40, 60, 80, 100]
      trust_labels = ['매우낮음', '낮음', '보통', '높음', '매우높음']

      out["trust_level_map"] = pd.cut(
          out["trust_score"],
          bins=trust_bins,
          labels=trust_labels,
          include_lowest=True
      )

      trust_level_map_dict = {
          '매우낮음': 0,
          '낮음': 1,
          '보통': 2,
          '높음': 3,
          '매우높음': 4
      }
      out["trust_level_map_num"] = out["trust_level_map"].map(trust_level_map_dict).astype("int8")

      if "trust_level" in out.columns:
          out.drop(columns=["trust_level"], inplace=True)
          out.drop(columns=["trust_level_map"], inplace=True)
    return out

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

df_score= trust_scores_RULES(df_data, RULES)

trust_bins = [0, 20, 40, 60, 80, 100]
trust_labels = ['매우낮음', '낮음', '보통', '높음', '매우높음']
df_data['trust_level'] = pd.cut(df_data['trust_score'],
                                         bins=trust_bins,
                                         labels=trust_labels,
                                         include_lowest=True)

print("신뢰도 점수 분포:")
trust_distribution = df_data['trust_level'].value_counts().sort_index()
print(trust_distribution)
print(f"\n신뢰도 점수 통계:")
print(df_data['trust_score'].describe())

def create_balanced_trust_dataset(df, samples_per_bin=None,val_ratio=0.2, test_size=0.2, random_state=42):

    if isinstance(df["trust_level"].dtype, CategoricalDtype):
        trust_labels = list(df["trust_level"].cat.categories)
    else:
        trust_labels = sorted(df["trust_level"].dropna().unique().tolist())

    print("원본 데이터 구간별 분포:")
    print(df["trust_level"].value_counts().sort_index())
    train_parts, val_parts, test_parts = [], [], []

    for level in trust_labels:
        level_df = df[df["trust_level"] == level]
        n = len(level_df)
        if n == 0:
            print(f"'{level}' 구간 데이터 없음 — 건너뜀")
            continue

        target_n = n if samples_per_bin is None else min(int(samples_per_bin), n)
        if target_n < n:
            level_df = level_df.sample(n=target_n, random_state=random_state)

        if len(level_df) < 3:
            print(f"'{level}' 구간 데이터 너무 적음 — 전부 train으로 이동 ({len(level_df)}개)")
            train_parts.append(level_df)
            continue

        temp_ratio = val_ratio + test_size
        bin_train, bin_temp = train_test_split(
            level_df, test_size=temp_ratio, random_state=random_state, shuffle=True
        )

        if len(bin_temp) >= 2:
            rel_test = test_size / (val_ratio + test_size)
            bin_val, bin_test = train_test_split(
                bin_temp, test_size=rel_test, random_state=random_state, shuffle=True
            )
        else:
            bin_val, bin_test = bin_temp, level_df.iloc[0:0]

        train_parts.append(bin_train)
        val_parts.append(bin_val)
        test_parts.append(bin_test)

        print(f"{level}: Train {len(bin_train)}개 / Val {len(bin_val)}개 / Test {len(bin_test)}개 (사용 {len(level_df)}/{n})")

    df_train = shuffle(pd.concat(train_parts, ignore_index=True), random_state=random_state).reset_index(drop=True)
    df_val   = shuffle(pd.concat(val_parts,   ignore_index=True), random_state=random_state).reset_index(drop=True)
    df_test  = shuffle(pd.concat(test_parts,  ignore_index=True), random_state=random_state).reset_index(drop=True)

    print("\n[Train set 구간별 분포]"); print(df_train["trust_level"].value_counts().sort_index())
    print("\n[Val set 구간별 분포]");   print(df_val["trust_level"].value_counts().sort_index())
    print("\n[Test set 구간별 분포]");  print(df_test["trust_level"].value_counts().sort_index())
    print(f"\nTrain: {len(df_train)}, Val: {len(df_val)}, Test: {len(df_test)}")

    return df_train, df_val, df_test

df_train, df_val, df_test = create_balanced_trust_dataset(
    df_data, samples_per_bin=None, val_ratio=0.2, test_size=0.2, random_state=42
)

df_train_processed = preprocess_df(df_train)
df_test_processed = preprocess_df(df_test)
df_val_processed = preprocess_df(df_val)

drop_cols = [c for c in ["trust_level_map_num","trust_score","net_trust_level"]
             if c in df_train_processed.columns]

X_train = df_train_processed.drop(columns=drop_cols)
y_train = df_train_processed["trust_level_map_num"]

X_val   = df_val_processed.drop(columns=drop_cols)
y_val   = df_val_processed["trust_level_map_num"]

X_test  = df_test_processed.drop(columns=drop_cols)
y_test  = df_test_processed["trust_level_map_num"]

model = XGBClassifier(
    n_estimators=1000,
    learning_rate=0.05,
    max_depth=3,
    subsample=0.6,
    colsample_bytree=0.6,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

labels = [0,1,2,3,4]
target_names = ['매우낮음(0)','낮음(1)','보통(2)','높음(3)','매우높음(4)']

y_pred = model.predict(X_test)

print("\n=== [Test Set] 성능 ===")
print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
print(f"F1 Score  : {f1_score(y_test, y_pred, average='macro'):.4f}")

print("\nConfusion Matrix (Test):")
print(confusion_matrix(y_test, y_pred, labels=labels))

print("\nClassification Report (Test):")
report = classification_report(
    y_test, y_pred, labels=labels, target_names=target_names, digits=4, output_dict=True
)
report_df = pd.DataFrame(report)
print(report_df)

importances = model.feature_importances_
feature_names = X_train.columns
importance_df = pd.DataFrame({
    "Feature": feature_names,
    "Importance": importances
}).sort_values(by="Importance", ascending=False)

print(importance_df.head(15))

def scenario_to_dataframe(
    scenario: dict,
    RULES: dict,
    *,
    trust_func,
    preprocess_func,
    return_score: bool = False
) -> pd.DataFrame | tuple[pd.DataFrame, float]:
    data = scenario.copy()

    for k, v in data.items():
        if v in ["", None]:
            data[k] = np.nan

    df = pd.DataFrame([data])

    df_scored = trust_func(df, RULES)

    tscore = float(df_scored["trust_score"].iloc[0]) if "trust_score" in df_scored.columns else np.nan

    df_processed = preprocess_func(df_scored)

    if return_score:
        return df_processed, tscore
    return df_processed


trust_labels = ['매우낮음', '낮음', '보통', '높음', '매우높음']

def predict_trust_level_for_scenario(scenario_data, model):
    if isinstance(scenario_data, pd.DataFrame):
        df = scenario_data.copy()
    elif isinstance(scenario_data, pd.Series):
        df = scenario_data.to_frame().T
    elif isinstance(scenario_data, dict):
        df = pd.DataFrame([scenario_data])
    else:
        raise TypeError("scenario_data must be DataFrame, Series, or dict")

    feats = list(getattr(model, "feature_names_in_", df.columns))
    for c in feats:
        if c not in df.columns:
            df[c] = 0
    df = df[feats]

    for c in df.columns:
        if df[c].dtype == "O":
            df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.fillna(0)

    proba = model.predict_proba(df)[0]
    pred_id = int(np.argmax(proba))

    model_classes = getattr(model, "classes_", np.arange(len(proba)))
    label_text = trust_labels[pred_id] if pred_id < len(trust_labels) else str(model_classes[pred_id])

    probs = {
        (trust_labels[i] if i < len(trust_labels) else str(model_classes[i])): float(proba[i])
        for i in range(len(proba))
    }

    return {
        "predicted_id": pred_id,
        "predicted_label": label_text,
        "confidence": float(proba[pred_id]),
        "probabilities": probs
    }


safe_regular = {
    'user_id': 'u-safe-001',
    'user_role': 'employee',
    'mfa_used': 1,
    'failed_attempts_recent': 0,
    'device_id': 'dev-safe-001',
    'os_name': 'Windows',
    'os_version': '10.0.0',
    'patch_age_days': 15,
    'disk_encrypt': 1,
    'src_ip': '10.0.1.5',
    'geo_country': 'KR',
    'network_type': 'office_lan',
    'proxy_vpn_tor': 'none',
    'tz_offset_minutes': 0,
    'locale_lang': 'ko-KR',
    'device_owner': 'company',
    'login_hour_local': 10,
    'impossible_travel': 0,
    'user_agent_fingerprint': 'ua-safe',
    'previous_success_login_ts': '2025-10-10T09:00:00Z',
    'job_title': 'Engineer',
    'department': 'R&D',
    'software_info': 'EDR/MDM 정책 준수',
    'user_info': '정규직',
    'time_info': '근무시간',
    'location_info': '국내',
    'network_context': '가정/모바일망',
    'behavior_context': '일반 조회/업로드',
    'auth_context': 'MFA',
    'access_resource_name': 'intra',
    'access_resource_sensitivity': 'low',
    'access_action': 'read',
    'trust_score': np.nan,
    'pdp_pep_decision': 'allow',
    'trust_level': np.nan
}

risky_guest = {
    'user_id': 'u-risk-001',
    'user_role': 'guest',
    'mfa_used': 0,
    'failed_attempts_recent': 4,
    'device_id': 'dev-risk-001',
    'os_name': 'Windows',
    'os_version': '6.3.0',
    'patch_age_days': 240,
    'disk_encrypt': 0,
    'src_ip': '203.0.113.77',
    'geo_country': 'RU',
    'network_type': 'cafe_open',
    'proxy_vpn_tor': 'none',
    'tz_offset_minutes': 0,
    'locale_lang': 'ko-KR',
    'device_owner': 'personal',
    'login_hour_local': 2,
    'impossible_travel': 1,
    'user_agent_fingerprint': 'ua-risk',
    'previous_success_login_ts': '2025-07-01T10:00:00Z',
    'job_title': 'Contractor',
    'department': 'External',
    'software_info': '컨테이너/앱 격리',
    'user_info': '외부 게스트',
    'time_info': '야간',
    'location_info': '해외 금지국',
    'network_context': '공용망',
    'behavior_context': '대량 전송',
    'auth_context': '비밀번호만',
    'access_resource_name': 'hr_db',
    'access_resource_sensitivity': 'high',
    'access_action': 'download',
    'trust_score': np.nan,
    'pdp_pep_decision': 'deny',
    'trust_level': np.nan
}

test_scenarios = [
    {"name": "안전한_정규직", "data": safe_regular},
    {"name": "위험한_게스트", "data": risky_guest},
]


print("\n=== 시나리오 구간 판단 테스트 ===")
for s in test_scenarios:
    df_proc, tscore = scenario_to_dataframe(
        s["data"],
        RULES,
        trust_func=trust_scores_RULES,
        preprocess_func=preprocess_df,
        return_score=True
    )

    if np.nanmax(tscore) <= 10:
        tscore = min(max(tscore * 10, 0), 100)

    r = predict_trust_level_for_scenario(df_proc, model)

    print(f"\n[{s['name']}] trust score : [{tscore:.2f}]")
    print(f"[{s['name']}] 예측: {r['predicted_id']} ({r['predicted_label']}), 확률={r['confidence']:.4f}")
    for k, v in r["probabilities"].items():
        print(f"  {k}: {v:.4f}")

artifact = {
    "model": model,
    "feature_columns": list(X_train.columns),
    "created_at": str(pd.Timestamp.utcnow()),
    "params": model.get_params()
}

joblib.dump(artifact, "zt_xgb_model.pkl")

