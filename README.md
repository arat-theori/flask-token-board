# 토큰 인증 게시판

Python Flask로 만든 간단한 로그인 및 게시판 예제입니다. 인증은 HttpOnly 쿠키에 저장한 `access_token`과 `refresh_token`으로 처리합니다.

## Docker 실행

```bash
docker compose up --build
```

브라우저에서 `http://localhost:5000`으로 접속합니다.

## 로컬 실행

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app run --debug
```

## 기능

- 회원가입
- 로그인 및 로그아웃
- Access token 3분 만료
- Refresh token 1시간 만료
- Refresh token이 유효하면 만료된 access token 자동 재발급
- 게시글 목록, 작성, 수정, 삭제
- SQLite 데이터 저장

## 기본 계정

앱 시작 시 아래 계정이 없으면 자동 생성됩니다.

| 아이디 | 비밀번호 |
| --- | --- |
| `arat` | `arat` |
| `tara` | `tara` |
