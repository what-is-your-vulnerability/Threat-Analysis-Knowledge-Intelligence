"""여러 모듈이 함께 쓰는 오류. config와 스캐너 어댑터가 서로를 import하지 않게 여기에 둔다."""


class ConfigError(ValueError):
    pass
