# app/main.py

from fastapi import FastAPI, Request, HTTPException, Response
import logging

# 디버깅을 위한 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 허용된 IP 목록 (메모리에 저장, 실제 환경에서는 Redis 등 사용)
ALLOWED_IPS = set()

app = FastAPI()

def get_client_ip(request: Request) -> str | None:
    """
    Nginx 프록시가 설정한 'x-real-ip' 헤더에서 클라이언트 IP를 일관되게 가져옵니다.
    """
    client_ip = request.headers.get("x-real-ip")
    # Docker Compose 환경에서는 curl 요청의 소스 IP가 Docker 네트워크 내부 IP로 보일 수 있습니다.
    # 예: 172.18.0.1
    # 이 IP를 기준으로 허용/차단하게 됩니다.
    return client_ip

@app.get("/getaccess")
def get_access(request: Request):
    """
    'x-real-ip' 헤더를 기반으로 클라이언트 IP를 허용 목록에 추가합니다.
    """
    client_ip = get_client_ip(request)
    logger.info(f"--- /getaccess 요청 수신 ---")
    logger.info(f"전체 헤더: {dict(request.headers)}")
    
    if client_ip:
        ALLOWED_IPS.add(client_ip)
        logger.info(f"✅ IP {client_ip}를 허용 목록에 추가했습니다. 현재 목록: {ALLOWED_IPS}")
        return {"message": f"IP {client_ip}의 접근이 허용되었습니다."}
    
    logger.error("🚫 'x-real-ip' 헤더를 찾을 수 없습니다. Nginx 설정을 확인하세요.")
    raise HTTPException(status_code=400, detail="'x-real-ip' header is missing.")


@app.get("/auth")
def authenticate_request(request: Request):
    """
    Nginx의 auth_request에 의해 호출되며, 'x-real-ip' 헤더의 IP가 허용 목록에 있는지 확인합니다.
    """
    client_ip = get_client_ip(request)
    logger.info(f"--- /auth 인증 요청 수신 ---")
    logger.info(f"인증 시도 IP: {client_ip}")

    if client_ip and client_ip in ALLOWED_IPS:
        logger.info(f"👍 접근 허용: {client_ip}")
        return Response(status_code=200)
    else:
        logger.warning(f"🚫 접근 거부: {client_ip}. (허용 목록: {ALLOWED_IPS})")
        raise HTTPException(status_code=403, detail="Access Denied")