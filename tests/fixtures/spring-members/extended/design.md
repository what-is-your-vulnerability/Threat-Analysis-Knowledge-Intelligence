# 회원 관리 설계(확장판)

## 4.5 회원 정지

POST /api/v1/admin/members/{id}/suspend 는 관리자만 쓸 수 있다.

## 4.6 회원 삭제

DELETE /api/v1/admin/members/{id} 는 관리자 권한이 있어야 한다.
