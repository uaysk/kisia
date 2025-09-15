# API 엔드포인트 문서

이 문서는 KISIA ZTNA PoC 프로젝트의 백엔드 API 엔드포인트를 설명합니다.

## 인증 (Authentication)

### `POST /api/users/login`

- **설명:** 일반 사용자 로그인
- **HTTP 메서드:** `POST`
- **인증:** 필요 없음
- **요청 형식:** `application/x-www-form-urlencoded`
  - `username`: 사용자 이름
  - `password`: 비밀번호
- **성공 응답 (`200 OK`):** `application/json`
  ```json
  {
    "access_token": "string",
    "token_type": "bearer"
  }
  ```
- **참고:** 성공 시 `access_token`이 HTTPOnly 쿠키로 설정됩니다.

### `POST /api/admin/login`

- **설명:** 관리자 로그인
- **HTTP 메서드:** `POST`
- **인증:** 필요 없음
- **요청 형식:** `application/x-www-form-urlencoded`
  - `username`: 관리자 이름
  - `password`: 비밀번호
- **성공 응답 (`200 OK`):** `application/json`
  ```json
  {
    "access_token": "string",
    "token_type": "bearer"
  }
  ```

### `GET /api/users/me`

- **설명:** 현재 로그인된 사용자 정보 조회
- **HTTP 메서드:** `GET`
- **인증:** 사용자 토큰 필요 (Bearer Token 또는 Cookie)
- **요청 형식:** 없음
- **성공 응답 (`200 OK`):** `application/json`
  ```json
  {
    "username": "string",
    "id": 0
  }
  ```

### `GET /api/admin/me`

- **설명:** 현재 로그인된 관리자 정보 조회
- **HTTP 메서드:** `GET`
- **인증:** 관리자 토큰 필요 (Bearer Token)
- **요청 형식:** 없음
- **성공 응답 (`200 OK`):** `application/json`
  ```json
  {
    "username": "string",
    "id": 0
  }
  ```

## ZTNA 핵심 (ZTNA Core)

### `GET /api/check_auth/{full_path}`

- **설명:** Nginx `auth_request`를 통해 서비스 접근 권한 확인. 사용자의 보안 점수와 서비스가 요구하는 점수를 비교합니다.
- **HTTP 메서드:** `GET`
- **인증:** 사용자 토큰 필요 (Cookie)
- **요청 형식:** 없음
- **성공 응답:**
  - `200 OK`: 접근 허용
  - `403 Forbidden`: 접근 거부 (점수 미달 또는 서비스 없음)
  - `503 Service Unavailable`: UEM 서비스 연결 불가

## 관리자 API (Admin APIs)

### 사용자 관리

#### `GET /api/admin/users`

- **설명:** 모든 사용자 목록 조회
- **HTTP 메서드:** `GET`
- **인증:** 관리자 토큰 필요
- **요청 형식:** 없음
- **성공 응답 (`200 OK`):** `application/json`
  ```json
  [
    {
      "username": "string",
      "id": 0
    }
  ]
  ```

#### `POST /api/admin/users`

- **설명:** 신규 사용자 생성
- **HTTP 메서드:** `POST`
- **인증:** 관리자 토큰 필요
- **요청 형식:** `application/json`
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **성공 응답 (`200 OK`):** `application/json`
  ```json
  {
    "username": "string",
    "id": 0
  }
  ```

#### `DELETE /api/admin/users/{user_id}`

- **설명:** 특정 사용자 삭제
- **HTTP 메서드:** `DELETE`
- **인증:** 관리자 토큰 필요
- **요청 형식:** 없음
- **성공 응답 (`200 OK`):** `application/json` (삭제된 사용자 정보)

### 관리자 계정 관리

#### `GET /api/admin/admins`

- **설명:** 모든 관리자 목록 조회
- **HTTP 메서드:** `GET`
- **인증:** 관리자 토큰 필요
- **요청 형식:** 없음
- **성공 응답 (`200 OK`):** `application/json`

#### `POST /api/admin/admins`

- **설명:** 신규 관리자 생성
- **HTTP 메서드:** `POST`
- **인증:** 관리자 토큰 필요
- **요청 형식:** `application/json`
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **성공 응답 (`200 OK`):** `application/json`

#### `DELETE /api/admin/admins/{admin_id}`

- **설명:** 특정 관리자 삭제
- **HTTP 메서드:** `DELETE`
- **인증:** 관리자 토큰 필요
- **요청 형식:** 없음
- **성공 응답 (`200 OK`):** `application/json` (삭제된 관리자 정보)

### 서비스 관리

#### `GET /api/admin/services`

- **설명:** 등록된 모든 서비스 목록 조회 (관리자용)
- **HTTP 메서드:** `GET`
- **인증:** 관리자 토큰 필요
- **요청 형식:** 없음
- **성공 응답 (`200 OK`):** `application/json`

#### `POST /api/admin/services`

- **설명:** 신규 서비스 등록. 등록 시 Nginx 설정이 자동으로 생성 및 리로드됩니다.
- **HTTP 메서드:** `POST`
- **인증:** 관리자 토큰 필요
- **요청 형식:** `application/json`
  ```json
  {
    "name": "string",
    "access_path": "/example",
    "upstream_url": "http://example.com",
    "required_score": 80
  }
  ```
- **성공 응답 (`200 OK`):** `application/json` (생성된 서비스 정보)

#### `DELETE /api/admin/services/{service_id}`

- **설명:** 특정 서비스 삭제. 삭제 시 Nginx 설정이 자동으로 제거 및 리로드됩니다.
- **HTTP 메서드:** `DELETE`
- **인증:** 관리자 토큰 필요
- **요청 형식:** 없음
- **성공 응답 (`200 OK`):** `application/json` (삭제된 서비스 정보)

## 공개 API (Public APIs)

### `GET /`

- **설명:** API 서버 동작 확인
- **HTTP 메서드:** `GET`
- **인증:** 필요 없음
- **요청 형식:** 없음
- **성공 응답 (`200 OK`):** `application/json`
  ```json
  {
    "message": "ZTNA PoC Backend is running"
  }
  ```

### `GET /api/services`

- **설명:** 등록된 모든 서비스 목록 조회 (공개용)
- **HTTP 메서드:** `GET`
- **인증:** 필요 없음
- **요청 형식:** 없음
- **성공 응답 (`200 OK`):** `application/json`

## 웹소켓 (WebSocket)

### `WS /ws/client`

- **설명:** 웹 대시보드 클라이언트와 서버 간의 실시간 통신을 위한 웹소켓 엔드포인트입니다. UEM Agent로부터 수신된 OS 스냅샷 정보를 브로드캐스트합니다.

### `WS /ws/uem`

- **설명:** UEM Agent와 서버 간의 실시간 통신을 위한 웹소켓 엔드포인트입니다. Agent로부터 OS 스냅샷을 수신합니다.
