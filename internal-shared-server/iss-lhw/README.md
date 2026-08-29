# ISS 웹 콘솔 (iss-lhw)

폐쇄망 내부 공유 서버(ISS)를 위한 Local Hosted Web 콘솔입니다. Angular · Tailwind CSS로 작성했고 Vite+(`vp`) 모노레포로 빌드합니다.

브라우저는 ISS의 TCP 바이너리 프로토콜을 직접 말할 수 없으므로, 이 웹은 `iss lhw` 루프백 HTTP 브리지를 경유합니다. 브리지는 요청을 검증된 `ISSClient` 경로(PSK 상호 인증 + ChaCha20-Poly1305 채널)로 중계하며, PSK와 암호 구현은 JVM 밖으로 나가지 않습니다.

## 구조

```text
apps/website     Angular 22 웹 콘솔 (zoneless, standalone, signals)
packages/utils   공용 TypeScript 패키지 (템플릿 유지)
```

- `apps/website/src/app/core` -> 인증 저장소, HTTP 인터셉터, API 클라이언트, 값 포맷 유틸
- `apps/website/src/app/views` -> 토큰 게이트, 콘솔 셸, 대시보드, 키 저장소 화면

## 개발

```bash
pnpm install

# 1) 타겟 ISS 서버와 브리지 기동 (저장소 루트에서)
iss serve --port 8443 --psk-file infra.psk
iss lhw   --port 8443 --psk-file infra.psk        # 기본 http-port 5874

# 2) Vite 개발 서버 (HMR, /api 는 브리지로 프록시)
vp -C apps/website dev
# 브리지 포트를 바꿨다면: LHW_PORT=9999 vp -C apps/website dev
```

검사·테스트·빌드는 Vite+ 표준 흐름을 따릅니다.

```bash
vp check                  # 포맷·린트·타입 검사
vp -C apps/website test   # vitest 단위 테스트
vp -C apps/website build  # dist/ 생성
```

## 배포

빌드된 `apps/website/dist`를 브리지의 `--web-dir`로 지정하면 브리지가 정적 웹을 함께 서빙합니다. 별도 웹 서버가 필요 없습니다.

```bash
iss lhw --port 8443 --psk-file infra.psk --web-dir apps/website/dist
```

기동 시 터미널에 1회 출력되는 접속 토큰을 `http://127.0.0.1:5874` 콘솔에 입력해 연결합니다.

## 보안 모델

- 브리지 바인드는 항상 루프백이며 해제 옵션이 없습니다
- 모든 API 요청은 기동 시 1회 발급되는 Bearer 토큰을 요구합니다. 브리지는 토큰 평문 대신 SHA3-256 다이제스트만 보관하고 상수 시간 비교로 검증합니다
- `Origin` 헤더가 있으면 루프백 오리진만 허용합니다
- 값은 목록에 노출되지 않고 명시적 열람 시에만 전송됩니다. API 응답은 `Cache-Control: no-store`이며 토큰·열람 값은 브라우저 메모리에만 유지됩니다(localStorage 미사용)
- ISS 연결은 요청마다 새로 열어 매 요청이 PSK 상호 인증을 다시 통과합니다
- 정적 웹은 CSP · `nosniff` · 경로 이탈 차단과 함께 서빙됩니다

## 참고

- Angular 22는 TypeScript `>=6.0 <6.1`을 요구하므로 `apps/website`만 로컬 `typescript ~6.0`을 사용합니다(워크스페이스 카탈로그는 TS 7)
- Angular 컴파일은 `@analogjs/vite-plugin-angular`가 수행하며 `tsconfig.app.json`(빌드) · `tsconfig.spec.json`(테스트)을 사용합니다. 두 파일의 `noEmit: false` 오버라이드는 플러그인 AOT 출력에 필요하므로 제거하면 안 됩니다
