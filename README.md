# Infrastructure Automation with Ansible

> KakaoCloud 환경에서 Ansible을 사용해 **VM 초기 구성, 보안 강화, 모니터링 에이전트 배포, 인프라 상태 검증**을 자동화한 운영 플레이북 리스트.  
> Puppet 기반 구성 관리와 병행하여, Puppet 전환 이전의 초기 프로비저닝과 원타임 작업에 Ansible을 활용.

---

## Overview

| 항목 | 내용 |
|---|---|
| **대상 환경** | KakaoCloud (Ubuntu 22.04 / 24.04, Rocky Linux 9) |
| **주요 목적** | VM 초기 프로비저닝, 보안 강화, 모니터링 스택 배포, Puppet 전환 |
| **연동 도구** | Prometheus, Grafana Loki, Filebeat, Promtail, Node Exporter |
| **관련 프로젝트** | [Detecting Drifts in Infrastructure with Puppet](https://github.com/HyunsGit/Detecting-Drifts-in-Infrastructure-with-Puppet) |

---

## OS 전략 및 Ansible의 한계

**Ansible은 구성 상태를 지속적으로 보장하지 못함.** 플레이북은 실행 시점에만 상태를 적용하며, 이후 누군가 설정을 수동으로 변경하더라도 자동으로 감지하거나 복구 불가. 이 문제를 해결하기 위해 **Puppet을 통한 드리프트 감지 및 지속 수렴(Continuous Enforcement)** 체계로 전환.

Puppet 에이전트는 현재 **Ubuntu 24.04**를 기준 OS로 지원.

```
[기존 운영 방식]                    [목표 운영 방식]
Ansible 원타임 적용                  Ubuntu 24.04 표준화
→ 설정 드리프트 발생 가능     →      Puppet 에이전트 자동 등록
→ 재적용 필요                        → 1시간 주기 드리프트 감지 및 자동 수렴
```

| 플레이북 | 적용 대상 | 비고 |
|---|---|---|
| `Default-Playbook-V3.yaml` | **모든 OS** (Ubuntu 22.04, 24.04, Rocky Linux 9 등) | Puppet 미적용 환경의 표준 초기화 |
| `Default-Playbook-V3-Final-Proxy.yaml` | **모든 OS** (Proxy 환경) | Proxy 경유가 필요한 네트워크 환경 |
| `TOBE-Default-Playbook-V3.yaml` | **Ubuntu 24.04** (Puppet 적용 가능 OS) | Puppet 전환 완료 후 신규 VM 투입 시 사용 |

---

## Repository Structure

```
ansible/
├── playbook/
│   ├── Default-Playbook-V3.yaml              # VM 신규 투입 표준 플레이북
│   ├── Default-Playbook-V3-Final-Proxy.yaml  # Proxy 환경용 표준 플레이북
│   ├── TOBE-Default-Playbook-V3.yaml         # Puppet 전환 이후 신규 투입 플레이북
│   ├── create_os_user.yaml                   # 기본 OS 계정 생성
│   ├── install_node_exporter.yaml            # Node Exporter 설치
│   ├── check_lvm_partition.yaml              # LVM 파티션 상태 확인
│   ├── nvme_lvm.yaml                         # NVMe LVM 구성
│   ├── modify/                               # 개별 설정 변경 플레이북
│   ├── verify/                               # 상태 검증 플레이북
│   ├── main/                                 # Puppet 전환·인프라 유틸
│   ├── middleware/                           # 미들웨어 설치 플레이북
│   └── j2/                                  # Jinja2 템플릿 기반 플레이북
├── roles/                                    # 서비스 설정 파일 및 systemd unit
├── templates/                                # Jinja2 템플릿 (Prometheus, Promtail 등)
└── scripts/                                  # 보조 쉘 스크립트
```

---

## Playbook Categories

### 1. 표준 VM 초기 투입

#### `Default-Playbook-V3.yaml` — 모든 OS 대상

Puppet이 적용되지 않은 **모든 OS**(Ubuntu 22.04, 24.04, Rocky Linux 9 등) 신규 VM에 실행하는 원스톱 초기화 플레이북. 아래 작업을 순서대로 수행:

| 단계 | 작업 | 비고 |
|---|---|---|
| 1 | Route53 A레코드 등록 | `amazon.aws.route53` 사용, AWS 자격증명은 Vault 참조 |
| 2 | KC 모니터링 에이전트 설치 | Ubuntu/Rocky 분기 처리 |
| 3 | OS 패키지 업데이트 및 필수 패키지 설치 | `apt` / `dnf` |
| 4 | 호스트명 변경 | inventory_hostname 기준 |
| 5 | 기본 OS 계정 생성 | scv/probe/drone/marine/zealot (UID/GID 고정) |
| 6 | Ulimit 최대화 | nofile/nproc = 655350 |
| 7 | Filebeat 설치 | ver. 8.17.10 |
| 8 | Node Exporter 설치 | ver. 1.6.0 |
| 9 | Promtail 설치 | Loki 로그 전송 |
| 10 | DNS 서버 등록 | systemd-resolved 설정 |
| 11 | NTP 서버 등록 | timesyncd / chrony |
| 12 | SSH 패스워드 인증 허용 | sshd_config 수정 |
| 13 | Timezone 동기화 | Asia/Seoul (KST) |

> ⚠️ Ansible은 이 설정들을 **실행 시점에만 적용**. 이후 드리프트가 발생해도 자동으로 감지하거나 복구하지 못함. 지속적인 상태 보장이 필요하다면 Puppet 전환을 권장.

#### `TOBE-Default-Playbook-V3.yaml` — Ubuntu 24.04 (Puppet 적용 대상)

**Ubuntu 24.04** 기준으로, Puppet 에이전트가 설치되어 구성 관리를 Puppet이 담당하는 환경에서 사용하는 경량 초기화 플레이북. Ansible은 Puppet이 관리할 수 없는 최초 부트스트랩 작업만 수행하고, 이후 설정 유지는 Puppet에 위임.

| 단계 | 작업 | 비고 |
|---|---|---|
| 1 | Route53 A레코드 등록 | AWS 자격증명은 Vault 참조 |
| 2 | KC 모니터링 에이전트 설치 | Puppet 모듈로 대체 예정 |
| 3 | 호스트명 변경 | inventory_hostname 기준 |
| 4 | Puppet 에이전트 설치 및 Master 등록 | 이후 모든 설정은 Puppet이 관리 |
| 5 | Timezone 동기화 | Asia/Seoul (KST) |

> 계정 생성, 보안 설정, 모니터링 에이전트, NTP/DNS 설정 등은 Puppet `security_hardening` / `monitoring` / `time` / `networking` 모듈이 지속적으로 관리함. 자세한 내용은 [Detecting Drifts in Infrastructure with Puppet](https://github.com/HyunsGit/Detecting-Drifts-in-Infrastructure-with-Puppet)를 참고.

---

### 2. 보안 강화 (`playbook/modify/`)

| 플레이북 | 내용 |
|---|---|
| `security-vulnerability.yaml` | PermitRootLogin 비활성화(U01), 패스워드 복잡도 설정(U02), SSH 배너 적용(U05) |
| `modify-ssh.yaml` | SSH 패스워드 인증 허용 (Password Authentication) |
| `add-sudoers.yaml` | sudoers에 사용자별 NOPASSWD 권한 추가 |
| `ephemeral-secvul.yaml` | 임시 보안 취약점 조치 (sshd 설정) |
| `ulimit.yaml` | nofile/nproc ulimit 최대화 (655350) |
| `stop-postfix.yaml` | 불필요한 postfix 서비스 중지 및 비활성화 |
| `cloud-init-dhcp-policy.yaml` | cloud-init DHCP 설정 비활성화 |

**패스워드 복잡도 정책 적용 예시 (`security-vulnerability.yaml`):**
```yaml
- name: change pwquality config
  replace:
    dest: /etc/security/pwquality.conf
    regexp: "{{ item.From }}"
    replace: "{{ item.To }}"
  with_items:
    - { From: '^dcredit.*', To: 'dcredit = -1' }  # 숫자 1개 이상
    - { From: '^ucredit.*', To: 'ucredit = -1' }  # 대문자 1개 이상
    - { From: '^lcredit.*', To: 'lcredit = -1' }  # 소문자 1개 이상
    - { From: '^minlen.*',  To: 'minlen = 8' }    # 최소 8자
```

---

### 3. 모니터링 스택 배포 (`playbook/middleware/`)

| 플레이북 | 내용 |
|---|---|
| `middleware/common/prometheus.yaml` | Prometheus 서버 설치 및 설정 |
| `middleware/common/promtail-agent.yaml` | Promtail 에이전트 설치 (Loki 연동) |
| `middleware/common/filebeats-vm.yaml` | Filebeat 7.x 설치 (VM용) |
| `middleware/common/kc-node-exporter.yaml` | KC Node Exporter 설치 |
| `middleware/common/grafana.yaml` | Grafana 설치 |
| `j2/prometheus-conf.yaml` | Jinja2 템플릿으로 Prometheus 설정 자동 생성 |
| `j2/alert-rule-instance-state.yaml` | 인스턴스 상태 알림 규칙 생성 |
| `j2/alert-rule-service-state.yaml` | 서비스 상태 알림 규칙 생성 |

**Prometheus 설정 자동화 흐름 (`j2/prometheus-conf.yaml`):**
```
Ansible inventory → gather_facts (hostname, IP)
       ↓
Jinja2 template (simplied-prometheus.conf.j2)
       ↓
/etc/prometheus/prometheus.yml (Prometheus 서버에 배포)
```

---

### 4. 네트워크 / DNS / NTP (`playbook/modify/`)

| 플레이북 | 내용 |
|---|---|
| `modify/ntp-server.yaml` | NTP 서버 변경 (timesyncd / chrony) |
| `modify/set-private-ntp-server.yaml` | 내부 NTP 서버 설정 |
| `modify/dns-server-v3.yaml` | DNS 서버 등록 |
| `modify/sync-timezone-kst.yaml` | Timezone Asia/Seoul 동기화 |

---

### 5. 상태 검증 (`playbook/verify/`)

| 플레이북 | 검증 내용 |
|---|---|
| `inspect-server.yaml` | 호스트명 / Timezone / NTP 상태 일괄 수집 및 파일 출력 |
| `check_ntp_status.yaml` | NTP 동기화 상태 확인 |
| `check_time_sync_status.yaml` | 시간 동기화 상태 확인 |
| `check-node-exporter-status.yaml` | Node Exporter 서비스 상태 확인 |
| `check-dns-status-default.yaml` | DNS 서버 응답 확인 |
| `check-ssh.yaml` | SSH 접속 가능 여부 확인 |
| `user-existence.yaml` | OS 계정 존재 여부 확인 |
| `timezone.yaml` | Timezone 설정 확인 |
| `filter_reachable_host_only.yaml` | 응답 가능한 호스트만 필터링 |
| `print-ansible-facts.yaml` | ansible_facts 전체 출력 |

---

### 6. Puppet 전환 지원 (`playbook/main/`)

Ansible로 운영하던 인프라를 Puppet으로 이전하는 작업을 지원하는 플레이북.

| 플레이북 | 내용 |
|---|---|
| `install-puppet-on-ubuntu.yaml` | Puppet 에이전트 설치 (Ubuntu 22.04 / 24.04) |
| `install-puppet-on-ubuntu22.yaml` | Ubuntu 22.04 전용 Puppet 설치 |
| `install-puppet-on-ubuntu24.yaml` | Ubuntu 24.04 전용 Puppet 설치 |
| `install-puppet-on-rocky.yaml` | Puppet 에이전트 설치 (Rocky Linux) |
| `install-puppet-master.yaml` | Puppet Master 서버 설치 및 초기 구성 |
| `refresh-puppet-agent.yaml` | `puppet agent -t` 원격 실행 |
| `ansible-puppet-transition.yaml` | Ansible → Puppet 전환 상태 점검 |
| `configure-fstrim.timer-on-ubuntu.yaml` | fstrim.timer systemd 서비스 구성 |

---

### 7. 감사 스크립트 (`scripts/`)

| 스크립트 | 내용 |
|---|---|
| `os_total_audit_1.0.sh` | OS 보안 감사 (v1.0) — KISA 기준 점검 항목 |
| `os_total_audit_2.0.sh` | OS 보안 감사 (v2.0) — 개선된 점검 항목 |
| `kr2_inspection.sh` | KR2 인프라 전체 점검 스크립트 |
| `motd.sh` | MOTD(Message of the Day) 배너 설정 |
| `ssh_banner.sh` | SSH 로그인 배너 설정 |

---

## Security Notes

AWS 자격증명 및 OS 계정 패스워드는 **Ansible Vault** 또는 **HashiCorp Vault**를 통해 관리. 플레이북에서 직접 하드코딩하지 않음.

```yaml
# ✅ 올바른 방식 — Vault 변수 참조
vars:
  aws_access_key: "{{ vault_aws_access_key }}"
  aws_secret_key: "{{ vault_aws_secret_key }}"

# ✅ vars_prompt — 실행 시 입력
vars_prompt:
  - name: access_id
    prompt: "Enter access_id: "
    private: false
```

---

## Tech Stack

- **Ansible** — 에이전트리스 자동화 (초기 프로비저닝 및 원타임 작업)
- **Ubuntu 24.04** — 표준 OS (Puppet 관리 대상), Ubuntu 22.04 / Rocky Linux 9 병행 운영 중
- **Prometheus + Node Exporter** — 메트릭 수집
- **Grafana Loki + Promtail** — 로그 수집
- **Filebeat 8.17.10** — 로그 전송
- **Puppet 8.x** — 구성 드리프트 감지 및 지속 수렴 (Ubuntu 24.04 기준)
- **KakaoCloud** — 인프라 환경
