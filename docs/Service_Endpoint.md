### Backend (FastAPI)
  
- GET / — 헬스 체크
- POST /api/users/login — 사용자 로그인 (OAuth2 form)
- POST /api/admin/login — 관리자 로그인 (OAuth2 form)
- GET /api/users/me — 현재 사용자 정보 (사용자 인증)
- GET /api/admin/me — 현재 관리자 정보 (관리자 인증)
- GET /api/check_auth/{full_path:path} — ZTNA 접근 검증(점수 기반, 사용자 인증)
- GET /api/services — 서비스 목록 (공개)

#### Admin APIs (관리자 인증)

- GET /api/admin/users — 사용자 목록
- POST /api/admin/users — 사용자 생성
- DELETE /api/admin/users/{user_id} — 사용자 삭제
- GET /api/admin/admins — 관리자 목록
- POST /api/admin/admins — 관리자 생성
- DELETE /api/admin/admins/{admin_id} — 관리자 삭제
- GET /api/admin/services — 서비스 목록(관리자 뷰)
- POST /api/admin/services — 서비스 생성 + Nginx 리로드
- DELETE /api/admin/services/{service_id} — 서비스 삭제 + Nginx 리로드

### WebSocket (FastAPI Router)

- WS /ws/client — 클라이언트 ↔ 서버프록시
- WS /ws/uem — UEM ↔ 서버프록시

### Dummy UEM (FastAPI)

- GET /score/{username} — 사용자 신뢰 점수 조회

### Nginx (Reverse Proxy / Static)

- INTERNAL /api/check_auth 접두 — 내부 서브요청용(외부 접근 불가), 백엔드로 프록시
- PROXY /api/ 접두 — 백엔드 API 프록시 (backend:8000/api/)
- 보호 대상 프록시(샘플)
    - /test — auth_request /api/check_auth/test 후 proxy_pass http://172.30.1.1:91
    - /whoami — auth_request /api/check_auth/whoami 후 proxy_pass http://172.30.1.1:90
- 정적 페이지
    - / (기본 user_login.html)
    - /user_login.html, /user_dashboard.html, /admin_login.html, /admin_dashboard.html