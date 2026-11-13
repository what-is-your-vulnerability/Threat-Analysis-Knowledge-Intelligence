# 허용한 호스트로만 나가는 HTTP(S) 프록시. 스캐너 준비 단계의 외부 접속을 허용 목록으로 제한한다(adapters/scanner/docker.py).
# 빌드할 때만 패키지를 받는다. 실행할 때 허용 호스트는 ALLOW_HOSTS(쉼표 구분)로 받는다.
# 빌드: docker build -t taki-egress-proxy:1 deploy/scanners/egress-proxy
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends tinyproxy && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
USER nobody
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
