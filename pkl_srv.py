from flask import Flask, request, jsonify
import joblib
import pandas as pd
import traceback
import os
import requests

# 여기에 당신의 기존 함수들이 같은 모듈에 있거나 import 가능해야 합니다:
# from your_module import trust_scores_RULES, preprocess_df, scenario_to_dataframe, predict_trust_level_for_scenario

MODEL_PKL_PATH = "zt_xgb_model.pkl"  # 실제 경로로 바꿀 것
REMOTE_SERVER_URL = "https://example.com/ingest"  # 결과를 전송할 서버 URL

app = Flask(__name__)

# 1) 모델(artifact) 로드
artifact = joblib.load(MODEL_PKL_PATH)
model = artifact.get("model")
feature_columns = artifact.get("feature_columns")  # 모델이 학습에 사용한 컬럼 리스트
created_at = artifact.get("created_at", "")

# 레이블 매핑 (코드 내에서 정의한 순서와 맞출 것)
trust_labels = ['매우낮음', '낮음', '보통', '높음', '매우높음']

def prepare_model_input(df_processed: pd.DataFrame):
    """모델에 넣을 수 있게 컬럼 정렬/누락 컬럼 처리 후 반환"""
    df = df_processed.copy()
    # 모델이 기대하는 컬럼이 없으면 0으로 채움
    for c in feature_columns:
        if c not in df.columns:
            df[c] = 0
    # 모델이 기대하는 순서로 정렬
    df = df[feature_columns]
    # 타입 안정화 (숫자형)
    for c in df.columns:
        if df[c].dtype == "O":
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    return df.fillna(0)

@app.route("/login", methods=["POST"])
def login_event():
    """
    클라이언트(로그인 프로세스)가 로그인 시나리오를 JSON으로 보내면:
    1) RULES 기반 score 계산
    2) 전처리
    3) 모델 예측
    4) 결과를 중앙 서버로 전송(또는 DB에 저장)
    """
    try:
        payload = request.get_json()
        # payload는 시나리오 dict (예: safe_regular 같은 구조)
        scenario = payload.get("scenario", payload)  # { "scenario": {...} } 또는 바로 {...}

        # 1) RULES 기반 점수 및 전처리 (사용자의 기존 함수 사용)
        # scenario_to_dataframe 함수가 trust_scores_RULES와 preprocess_df를 사용하도록 구현되어 있어야 함
        df_proc, tscore = scenario_to_dataframe(
            scenario, RULES, trust_func=trust_scores_RULES, preprocess_func=preprocess_df, return_score=True
        )

        # 2) 모델 입력 준비
        X = prepare_model_input(df_proc)

        # 3) 예측
        proba = model.predict_proba(X)[0]
        pred_idx = int(proba.argmax())
        pred_label = trust_labels[pred_idx] if pred_idx < len(trust_labels) else str(model.classes_[pred_idx])
        confidence = float(proba[pred_idx])
        probs = {trust_labels[i]: float(proba[i]) for i in range(len(proba))}

        result = {
            "trust_score_rules": float(tscore),
            "predicted_id": pred_idx,
            "predicted_label": pred_label,
            "confidence": confidence,
            "probabilities": probs,
            "model_created_at": created_at
        }

        # 4) 결과를 중앙 서버로 전송 (선택)
        try:
            # 필요한 헤더/인증 넣기
            headers = {"Content-Type": "application/json", "Authorization": "Bearer YOUR_API_TOKEN"}
            # 전송 payload: 로그인 시나리오 + 결과
            send_payload = {"scenario": scenario, "result": result}
            resp = requests.post(REMOTE_SERVER_URL, json=send_payload, headers=headers, timeout=5)
            result["remote_server_status"] = {"status_code": resp.status_code, "response_text": resp.text}
        except Exception as e:
            # 전송 실패해도 로컬로 결과 반환(에러 로깅)
            result["remote_server_status"] = {"error": str(e)}

        return jsonify({"success": True, "result": result}), 200

    except Exception as e:
        tb = traceback.format_exc()
        return jsonify({"success": False, "error": str(e), "traceback": tb}), 500

if __name__ == "__main__":
    # 개발 서버: 내부 테스트용. 실제 배포는 gunicorn 사용 권장.
    app.run(host="0.0.0.0", port=5000, debug=True)


#테스트
#curl -X POST http://localhost:5000/login \
#  -H "Content-Type: application/json" \
#  -d '{"user_id":"u-safe-001","user_role":"employee","mfa_used":1,"failed_attempts_recent":0, "os_version":"10.0.0","patch_age_days":15,"geo_country":"KR","network_type":"office_lan","login_hour_local":10, "previous_success_login_ts":"2025-10-10T09:00:00Z"}'
