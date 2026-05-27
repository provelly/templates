# SQL 인젝션 취약점 탐지 템플릿 모음

## 개요

이 디렉토리는 **Nuclei** 웹 취약점 스캐너 형식의 SQL 인젝션 탐지 YAML 템플릿을 포함합니다.
총 **35개 템플릿**이 제공되며, 다양한 데이터베이스, 인젝션 유형, 공격 벡터를 포괄합니다.

---

## 템플릿 목록

### 🔴 에러 기반 (Error-Based) SQL 인젝션 — 7개

| 파일명 | 대상 DB | 설명 |
|--------|--------|------|
| `sqli-error-based-mysql.yaml` | MySQL | MySQL 에러 메시지 기반 탐지 |
| `sqli-error-based-mssql.yaml` | MSSQL | Microsoft SQL Server 에러 탐지 |
| `sqli-error-based-oracle.yaml` | Oracle | ORA-XXXXX 에러 코드 탐지 |
| `sqli-error-based-postgresql.yaml` | PostgreSQL | PostgreSQL 에러 패턴 탐지 |
| `sqli-error-based-sqlite.yaml` | SQLite | SQLite 에러 탐지 |
| `sqli-error-based-db2.yaml` | IBM DB2 | DB2 SQLCODE 에러 탐지 |
| `sqli-error-based-mariadb.yaml` | MariaDB | MariaDB 특화 에러 탐지 |
| `sqli-error-based-sybase.yaml` | Sybase | SAP ASE 에러 탐지 |

### 🟡 블라인드 SQL 인젝션 — 8개

| 파일명 | 유형 | 설명 |
|--------|------|------|
| `sqli-boolean-blind.yaml` | Boolean | True/False 응답 차이 분석 |
| `sqli-time-based-blind-mysql.yaml` | Time-based | MySQL SLEEP() 함수 활용 |
| `sqli-time-based-blind-mssql.yaml` | Time-based | MSSQL WAITFOR DELAY |
| `sqli-time-based-blind-postgresql.yaml` | Time-based | PostgreSQL pg_sleep() |
| `sqli-time-based-oracle.yaml` | Time-based | Oracle DBMS_PIPE 활용 |
| `sqli-blind-boolean-binary-search.yaml` | Boolean | ASCII 이진 탐색 데이터 추출 |
| `sqli-response-diff-detection.yaml` | Differential | 응답 차이 분석 탐지 |
| `sqli-out-of-band-dns.yaml` | OOB/DNS | DNS 채널 데이터 유출 탐지 |

### 🔴 심각도 높은 공격 기법 — 5개

| 파일명 | 유형 | 설명 |
|--------|------|------|
| `sqli-union-based.yaml` | UNION | UNION SELECT 데이터 추출 |
| `sqli-stacked-queries.yaml` | Stacked | 세미콜론 다중 쿼리 실행 |
| `sqli-xml-xpath-mysql.yaml` | XML/XPath | ExtractValue/UpdateXML 에러 추출 |
| `sqli-file-read-write-mysql.yaml` | File R/W | LOAD_FILE/INTO OUTFILE 악용 |
| `sqli-mssql-xp-cmdshell.yaml` | RCE | xp_cmdshell 원격 코드 실행 |

### 🟠 공격 벡터별 탐지 — 10개

| 파일명 | 벡터 | 설명 |
|--------|------|------|
| `sqli-login-bypass.yaml` | 인증 우회 | 로그인 폼 SQL 인젝션 |
| `sqli-post-body.yaml` | POST Body | 폼 데이터 파라미터 |
| `sqli-http-header.yaml` | HTTP 헤더 | User-Agent, Referer, X-Forwarded-For |
| `sqli-cookie-based.yaml` | Cookie | 쿠키 값 기반 인젝션 |
| `sqli-json-body.yaml` | JSON API | REST API JSON 본문 |
| `sqli-xml-input.yaml` | XML/SOAP | SOAP 및 XML API |
| `sqli-graphql-injection.yaml` | GraphQL | GraphQL 쿼리 인젝션 |
| `sqli-multipart-form.yaml` | File Upload | 파일 업로드 파라미터 |
| `sqli-rest-api-path.yaml` | REST Path | URL 경로 파라미터 |
| `sqli-mass-assignment-bulk.yaml` | Bulk | 대량 할당 및 벌크 처리 |

### 🟡 특수/고급 기법 — 5개

| 파일명 | 유형 | 설명 |
|--------|------|------|
| `sqli-second-order.yaml` | 2차 인젝션 | 저장 후 트리거되는 인젝션 |
| `sqli-waf-bypass.yaml` | WAF 우회 | 인코딩/주석/대소문자 우회 |
| `sqli-order-by-sort.yaml` | ORDER BY | 정렬 파라미터 인젝션 |
| `sqli-truncation-attack.yaml` | 트렁케이션 | SQL 절단 공격 |
| `sqli-orm-hql-injection.yaml` | ORM/HQL | Hibernate HQL 인젝션 |
| `sqli-nosql-mongodb.yaml` | NoSQL | MongoDB 연산자 인젝션 |

### 🔵 포괄적 스캔 — 3개

| 파일명 | 유형 | 설명 |
|--------|------|------|
| `sqli-search-parameter.yaml` | 검색 | 검색/필터 파라미터 |
| `sqli-pagination-limit-offset.yaml` | 페이지네이션 | LIMIT/OFFSET 파라미터 |
| `sqli-integer-parameter.yaml` | 정수형 | 숫자 파라미터 특화 |
| `sqli-generic-error-detection.yaml` | 범용 | 모든 DB 공통 에러 탐지 |
| `sqli-fuzzing-common-payloads.yaml` | 퍼징 | 대량 페이로드 퍼징 |

---

## 사용 방법

### Nuclei 설치
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### 단일 템플릿 실행
```bash
nuclei -u https://target.com -t sqli-error-based-mysql.yaml
```

### 디렉토리 전체 실행
```bash
nuclei -u https://target.com -t ./sqli-templates/
```

### 특정 태그만 실행
```bash
# 에러 기반만
nuclei -u https://target.com -t ./sqli-templates/ -tags error-based

# 블라인드 탐지만
nuclei -u https://target.com -t ./sqli-templates/ -tags time-based,blind

# critical/high 심각도만
nuclei -u https://target.com -t ./sqli-templates/ -severity critical,high
```

### 대상 목록으로 실행
```bash
nuclei -l targets.txt -t ./sqli-templates/ -o results.txt
```

### 타임아웃 조정 (Time-based 탐지 시)
```bash
nuclei -u https://target.com -t ./sqli-templates/ -timeout 15
```

---

## 주의사항

> ⚠️ **이 템플릿은 허가된 보안 테스트 환경에서만 사용해야 합니다.**
> 승인 없이 타인의 시스템에 사용하는 것은 불법입니다.
> 버그 바운티 또는 침투 테스트 계약 범위 내에서만 활용하세요.

---

## 취약점 유형별 우선 탐지 권장 순서

1. `sqli-generic-error-detection.yaml` — 빠른 초기 스캔
2. `sqli-boolean-blind.yaml` — 블라인드 여부 확인
3. 데이터베이스 특화 에러 기반 템플릿
4. Time-based 블라인드 템플릿
5. UNION, Stacked 등 고급 기법

---

## 조치 방법 (공통)

1. **Prepared Statement / Parameterized Query** 사용 (최우선)
2. 입력값 타입 및 형식 검증
3. 에러 메시지 외부 노출 차단
4. 데이터베이스 계정 최소 권한 적용
5. WAF(웹 방화벽) 적용
6. 정기적인 보안 점검 및 DAST 스캔
