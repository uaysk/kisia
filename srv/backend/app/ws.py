# app/ws.py

import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Set

router = APIRouter()

# 연결 관리
connected_clients: Set[WebSocket] = set()
connected_uems: Set[WebSocket] = set()

@router.websocket("/ws/client")
async def websocket_client_endpoint(websocket: WebSocket):
    """
    클라이언트 <-> 서버프록시 웹소켓 연결
    """
    await websocket.accept()
    connected_clients.add(websocket)
    
    try:
        while True:
            # 클라이언트로부터 데이터 수신
            data = await websocket.receive_text()
            
            # 연결된 모든 UEM에 데이터 전달
            for uem in list(connected_uems):
                try:
                    await uem.send_text(data)
                except:
                    connected_uems.remove(uem)
                    
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

@router.websocket("/ws/uem")
async def websocket_uem_endpoint(websocket: WebSocket):
    """
    UEM <-> 서버프록시 웹소켓 연결
    """
    await websocket.accept()
    connected_uems.add(websocket)
    
    try:
        while True:
            # UEM으로부터 데이터 수신
            data = await websocket.receive_text()
            
            # 연결된 모든 클라이언트에 데이터 전달
            for client in list(connected_clients):
                try:
                    await client.send_text(data)
                except:
                    connected_clients.remove(client)
                    
    except WebSocketDisconnect:
        connected_uems.remove(websocket)