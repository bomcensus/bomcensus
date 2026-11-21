# bomcensus

[English](README.md)

bomcensus는 서버·컨테이너·쿠버네티스에 설치되고 실행 중인 소프트웨어를 수집해 SBOM으로 관리하고, 취약점 권고와 대조합니다.

## 상태

Linux Agent(connect·listen 모드), SSH를 통한 Agentless 수집, Kubernetes 인벤토리와 exec 수집, Agent 자동 업데이트, 웹 콘솔이 구현되어 있습니다. 취약점 대조, SBOM 내보내기, Windows 지원은 아직 구현되지 않았습니다.

## 시작하기

- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): Docker Compose, Helm, systemd로 서버·Agent·Scanner를 빌드하고 실행하는 방법 (영문)
- [docs/SECURITY.md](docs/SECURITY.md): 보안 설계, 권한 구성, 알려진 한계 (영문)
- [docs/PROTOCOL.md](docs/PROTOCOL.md): Agent 프로토콜의 서명과 비밀값 암호화 (영문)

## 라이선스

bomcensus는 [AGPL-3.0-only](LICENSE)와 JC-Lab의 상용 라이선스로 이루어진 이중 라이선스로 제공됩니다. [LICENSING.ko.md](LICENSING.ko.md)를 참고하십시오.

"bomcensus"는 JC-Lab의 상표입니다. [LICENSING.ko.md](LICENSING.ko.md#상표)를 참고하십시오.

기여하려면 CLA 서명이 필요합니다. [CONTRIBUTING.ko.md](CONTRIBUTING.ko.md)를 참고하십시오.
