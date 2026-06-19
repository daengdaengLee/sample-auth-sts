# sample-auth-sts

> AWS STS 를 활용한 인증 시스템 구현 샘플

## 개요

이 프로젝트는 워크로드가 이미 보유한 AWS IAM 신원을 AWS STS의 `GetCallerIdentity`로 증명(Proof of Possession)하여, 별도의 인증 시스템에 연합(federate)하는 방식을 보여주는 샘플입니다.
레퍼런스는 HashiCorp Vault의 AWS(IAM) auth method와 AWS IAM Authenticator for Kubernetes이며, 둘 다 동일한 PoP 기반 Workload Identity Federation 구현입니다.

### Workload Identity Federation 란

{TODO}

### Proof of Possession (PoP) 란

{TODO}

### 인증 흐름

{TODO}

### 보안 고려사항

<!-- 개념 담당: 위협 모델과 설계 근거(replay·confused deputy 공격, 서버 바인딩 헤더가 필요한 이유 등). 구체적 구현은 구현 가이드의 서버/클라이언트 > 보안 고려사항에서 다룬다. -->

{TODO}

## 구현 가이드

### 아키텍처

{TODO}

### 요구 사항

{TODO}

### 설정

{TODO}

### 서버

{TODO}

#### 보안 고려사항

<!-- 구현 담당(서버 측): 서버 바인딩 헤더 검증, STS 엔드포인트 allowlist, 반환 ARN 검증 등. 개념·위협 모델은 개요 > 보안 고려사항 참고. -->

{TODO}

### 클라이언트

{TODO}

#### 보안 고려사항

<!-- 구현 담당(클라이언트 측): 서명 요청에 서버 바인딩 헤더 포함, pre-signed 요청 만료 설정 등. 개념·위협 모델은 개요 > 보안 고려사항 참고. -->

{TODO}

### 실행 및 데모

{TODO}

## 제한 사항

{TODO}

## 참고 자료

{TODO}
