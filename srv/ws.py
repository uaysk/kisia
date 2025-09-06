# app/ws.py

import json
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Set

logger = logging.getLogger(__name__)
router = APIRouter()

# 연결 관리
connected_clients: Set[WebSocket] = set()
connected_uems: Set[WebSocket] = set()

async def calculate_trust_score(data: dict) -> float:
    """
    신뢰도 점수 산정 모델 (샘플)
    실제로는 ML/DL 모델 로직이 들어갈 수 있음
    """
    # 단순 예시: 데이터 길이 기반 가짜 점수
    score = len(json.dumps(data)) % 100 / 100
    logger.info(f"📊 신뢰도 점수 산정: {score}")
    return score


@router.websocket("/ws/client")
async def websocket_client_endpoint(websocket: WebSocket):
    """
    클라이언트 <-> 서버프록시
    """
    await websocket.accept()
    connected_clients.add(websocket)
    logger.info(f"📡 클라이언트 연결됨: {websocket.client}")

    try:
        while True:
            data = await websocket.receive_text()
            logger.info(f"클라이언트 → 서버프록시: {data}")

            # UEM이 연결되어 있으면 UEM에 요청 전달
            if connected_uems:
                for uem in connected_uems:
                    await uem.send_text(data)
            else:
                logger.warning("⚠️ 현재 연결된 UEM이 없음")

    except WebSocketDisconnect:
        connected_clients.remove(websocket)
        logger.warning(f"❌ 클라이언트 연결 해제: {websocket.client}")


@router.websocket("/ws/uem")
async def websocket_uem_endpoint(websocket: WebSocket):
    """
    UEM <-> 서버프록시
    """
    await websocket.accept()
    connected_uems.add(websocket)
    logger.info(f"🔌 UEM 연결됨: {websocket.client}")

    try:
        while True:
            data = await websocket.receive_text()
            logger.info(f"UEM → 서버프록시: {data}")

            # 신뢰도 점수 산정
            try:
                parsed_data = json.loads(data)
            except Exception:
                parsed_data = {"raw": data}

            score = await calculate_trust_score(parsed_data)

            # 신뢰도 점수 기준 판단
            if score >= 0.5:
                decision = {"status": "allow", "score": score}
                logger.info(f"✅ 접근 허용 (score={score})")
            else:
                decision = {"status": "deny", "score": score}
                logger.warning(f"🚫 접근 차단 (score={score})")

            # 클라이언트에게 결과 전달
            for client in connected_clients:
                await client.send_text(json.dumps(decision))

    except WebSocketDisconnect:
        connected_uems.remove(websocket)
        logger.warning(f"❌ UEM 연결 해제: {websocket.client}")
