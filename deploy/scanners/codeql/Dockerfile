# CodeQL 번들 이미지. 빌드할 때만 번들을 받고, 검사는 --network none으로 돈다.
# 빌드: docker build --platform linux/amd64 --build-arg CODEQL_SHA256=<공식 SHA-256> -t taki-codeql:2.27.4 deploy/scanners/codeql
FROM --platform=linux/amd64 debian:bookworm-slim

ARG CODEQL_VERSION=2.27.4
ARG CODEQL_SHA256
RUN test -n "$CODEQL_SHA256" || (echo "CODEQL_SHA256 빌드 인자가 필요하다" >&2; exit 1)

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL -o /tmp/codeql.tar.gz \
    "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz" \
 && echo "${CODEQL_SHA256}  /tmp/codeql.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/codeql.tar.gz -C /opt \
 && rm /tmp/codeql.tar.gz \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# 번들의 미리 컴파일한 쿼리(.codeql/precompiled/*.qlx)가 uid 1001 전용(0600)이라 --user로 돌리면 못 읽고 다시 컴파일하다 메모리가 모자란다.
# 다운로드 층을 다시 받지 않게 따로 둔다.
RUN find /opt/codeql ! -perm -o=r -exec chmod a+r {} +

ENV PATH="/opt/codeql:${PATH}"
RUN useradd --create-home --uid 10001 scanner
USER scanner
