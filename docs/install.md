# 설치 방법
아래의 명령어를 통해 백엔드 서버를 설치할 수 있습니다.

    git pull https://github.com/uaysk/kisia
    cd kisia/srv
    docker compose up --build -d
   만약 Grafana 대시보드를 통해 유저의 접속 위치를 지도상에 표시하고 싶다면 [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) 에서 GeoLite2-City.mmdb를 다운로드 받은 후 kisia/srv/monitoring/geoip 디렉터리에 위치시켜야 합니다.

성공적으로 서비스가 배포되었다면 localhost:80/user_login.html 으로 접속하였을 경우 유저 로그인 페이지를 확인할 수 있습니다.
처음에는 관리자 계정이 존재하지 않아 kisia/srv/backend/app/scripts/create_admin_admin.py 스크립트를 사용하여 관리자를 생성하여야 합니다. 생성 후 localhost:80/admin_login.html 에 접속하여 id, pw 모두 admin을 사용하여 로그인이 가능합니다.