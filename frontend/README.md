# bomcensus frontend

관리 콘솔. 지금은 서버 없이 `app/mock`의 정적 데이터로 동작하는 목업이다.

## 실행

Node 26과 pnpm이 필요하다.

```sh
nvm use
pnpm install
pnpm dev          # http://localhost:3000
pnpm typecheck
pnpm generate     # 정적 빌드: .output/public
```

## 구조

```
app/
  pages/         화면
  components/    공용 컴포넌트
  layouts/       좌측 메뉴와 상단 바
  mock/          목업 데이터와 조회 함수
  types/         도메인 타입
  utils/         라벨, 표시 형식
  assets/css/    색·글꼴 토큰 (main.css)
```

- 페이지는 `~/mock`의 함수만 쓴다. 서버 API가 생기면 `app/mock/index.ts`의 함수를 OpenAPI에서 생성한 클라이언트 호출로 바꾼다.
- 색과 글꼴은 `app/assets/css/main.css`의 토큰만 쓴다.
- TypeScript는 6.x로 고정했다. `vue-tsc`가 7.x를 아직 지원하지 않는다.
