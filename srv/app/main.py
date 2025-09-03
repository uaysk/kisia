from fastapi import FastAPI, Request, HTTPException, Response

# 개념 증명을 위해 파이썬 메모리에 허용된 IP 목록을 저장합니다.
# 실제 프로덕션 환경에서는 Redis나 데이터베이스를 사용해야 합니다.
ALLOWED_IPS = set()

app = FastAPI()

@app.get("/getaccess")
def get_access(request: Request):
    """
    요청을 보낸 클라이언트의 IP를 허용 목록에 추가합니다.
    """
    client_ip = request.client.host
    if client_ip:
        ALLOWED_IPS.add(client_ip)
        print(f"✅ IP {client_ip} has been added to the allow list. Current list: {ALLOWED_IPS}")
        return {"message": f"IP {client_ip} is now allowed."}
    return {"message": "Could not determine client IP."}


@app.get("/auth")
def authenticate_request(request: Request):
    """
    Nginx의 auth_request에 의해 호출되는 인증 엔드포인트입니다.
    X-Real-IP 헤더를 통해 실제 클라이언트 IP를 확인합니다.
    """
    # Nginx가 proxy_set_header를 통해 전달한 실제 클라이언트 IP
    client_ip = request.headers.get("x-real-ip")

    if client_ip in ALLOWED_IPS:
        print(f"👍 Access granted for IP: {client_ip}")
        # IP가 허용 목록에 있으면 200 OK 응답
        return Response(status_code=200)
    else:
        print(f"🚫 Access denied for IP: {client_ip}")
        # 허용 목록에 없으면 403 Forbidden 예외 발생
        raise HTTPException(status_code=403, detail="Access Denied")