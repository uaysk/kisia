# 설치 방법
아래의 명령어를 통해 백엔드 서버를 설치할 수 있습니다.

    git pull https://github.com/uaysk/kisia
    cd kisia/srv
    docker compose up --build -d
   만약 Grafana 대시보드를 통해 유저의 접속 위치를 지도상에 표시하고 싶다면 [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) 에서 GeoLite2-City.mmdb를 다운로드 받은 후 kisia/srv/monitoring/geoip 디렉터리에 위치시켜야 합니다.

성공적으로 서비스가 배포되었다면 localhost:80/user_login.html 으로 접속하였을 경우 유저 로그인 페이지를 확인할 수 있습니다.

<img width="1440" height="813" alt="image" src="https://github.com/user-attachments/assets/b0261304-86ce-4ce1-9fd3-a18f92ef2187" />

<img width="1440" height="813" alt="image" src="https://github.com/user-attachments/assets/5a8dca70-d89f-4b8d-86a5-4f5a00a1d07e" />

처음에는 관리자 계정이 존재하지 않아 kisia/srv/backend/app/scripts/create_admin_admin.py 스크립트를 사용하여 관리자를 생성하여야 합니다. 생성 후 localhost:80/admin_login.html 에 접속하여 id, pw 모두 admin을 사용하여 로그인이 가능합니다.

<img width="1440" height="813" alt="image" src="https://github.com/user-attachments/assets/76f0c104-aa4e-4134-9938-6b13039fe686" />

<img width="1440" height="813" alt="image" src="https://github.com/user-attachments/assets/8f9ec6ee-5694-4d54-ba76-e77c9b973eb8" />
