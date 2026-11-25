# bomcensus

[English](README.md)

bomcensus는 서버·컨테이너·쿠버네티스에 설치되고 실행 중인 소프트웨어를 수집해 SBOM으로 관리하고, 취약점 권고와 대조합니다.

## 상태

Linux Agent(connect·listen 모드), SSH를 통한 Agentless 수집, Kubernetes 인벤토리와 exec 수집, 취약점 대조, 패키지 파일 무결성 검사, Agent 자동 업데이트, 웹 콘솔이 구현되어 있습니다. 모든 명령은 Windows(amd64, arm64)에서도 빌드되고 실행되며, Windows Agent는 현재 호스트 정보만 보고합니다.

## 설치

최신 stable 릴리즈를 명령 하나로 설치합니다. Linux 기준이며, 서버는 compose 플러그인이 있는 Docker가, Agent는 root 권한과 systemd가 필요합니다.

```sh
# 서버 (Docker Compose의 PostgreSQL + bomcensus)
curl -fsSL https://github.com/bomcensus/bomcensus/releases/latest/download/install.sh \
    | bash -s -- server --env AGENT_SERVER_NAMES=bomcensus.example.com

# 호스트 Agent (Register Key의 enrollment 문자열 사용)
curl -fsSL https://github.com/bomcensus/bomcensus/releases/latest/download/install.sh \
    | sudo BOMCENSUS_TOKEN=bc1.... bash -s -- agent --server https://bomcensus.example.com:8443
```

`--rc`는 프리릴리즈까지 대상에 포함하고, `--version X.Y.Z`는 버전을 고정하며, `--attest prefer|required|disabled`는 GitHub CLI로 하는 빌드 출처(provenance) 검증을 조절합니다(기본 `prefer`: `gh`가 설치되어 있고 로그인된 경우에만 검증). 자세한 내용과 서버 옵션은 [DEPLOYMENT.md, Quick install](docs/DEPLOYMENT.md#quick-install) (영문)을 참고하십시오.

## 시작하기

- `make demo-up`: 예제 데이터가 들어간 로컬 데모, http://localhost:8080 (admin / demo). [DEPLOYMENT.md §2.9](docs/DEPLOYMENT.md#29-demo) 참고 (영문)
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): Docker Compose, Helm, systemd, Windows 서비스로 서버·Agent·Scanner를 빌드하고 실행하는 방법 (영문)
- [docs/SECURITY.md](docs/SECURITY.md): 보안 설계, 권한 구성, 알려진 한계 (영문)
- [docs/PROTOCOL.md](docs/PROTOCOL.md): Agent 프로토콜, 서명과 비밀값 암호화 (영문)
- [docs/EXTENDING.md](docs/EXTENDING.md): 직접 만든 Go 모듈에서 server, agent, scanner를 빌드하는 방법. 인증, 인가, 데이터 범위, agent 채널 (영문)
- [docs/GO_SYMBOLS.md](docs/GO_SYMBOLS.md): Go 심볼 확인, 지원하는 실행 파일과 테스트한 Go 버전 (영문)
- [docs/FILE_INTEGRITY.md](docs/FILE_INTEGRITY.md): 패키지 파일 무결성 검사, 일정과 허용 규칙 (영문)
- [docs/RELEASING.md](docs/RELEASING.md): 배포되는 이미지·차트·바이너리와 검증 방법 (영문)

## 라이선스

bomcensus는 [AGPL-3.0-only](LICENSE)와 JC-Lab의 상용 라이선스로 이루어진 이중 라이선스로 제공됩니다. [LICENSING.ko.md](LICENSING.ko.md)를 참고하십시오.

"bomcensus"는 JC-Lab의 상표입니다. [LICENSING.ko.md](LICENSING.ko.md#상표)를 참고하십시오.

기여하려면 CLA 서명이 필요합니다. [CONTRIBUTING.ko.md](CONTRIBUTING.ko.md)를 참고하십시오.
