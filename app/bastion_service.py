"""
BASTION 서비스 - Caldera와 Wazuh 통합 핵심 로직
"""

import aiohttp
import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from aiohttp import web
from dateutil import parser as date_parser

# loading integration_engine

try:
    from .integration_engine import IntegrationEngine
except Exception as e:
    import logging
    logging.getLogger('bastion').warning(f'[BASTION] IntegrationEngine 로컬 import 실패, fallback 사용: {e}')
    from importlib import import_module
    IntegrationEngine = import_module('integration_engine').IntegrationEngine

class BASTIONService:
    """Caldera-Wazuh 통합 서비스"""

    # HTTP 타임아웃 상수 (초 단위)
    TIMEOUT_HEALTH = 5      # Health check (빠른 응답 필요)
    TIMEOUT_AUTH = 10       # 인증 및 짧은 API 호출
    TIMEOUT_QUERY = 30      # 데이터 조회 및 복잡한 쿼리

    # Wazuh Rule ID → MITRE ATT&CK Technique 매핑
    # Wazuh 기본 규칙에 MITRE 태그가 없으므로 수동 매핑
    RULE_MITRE_MAPPING = {
        # 인증 및 계정
        '5715': 'T1078',      # SSH authentication success → Valid Accounts
        '5501': 'T1078',      # PAM: Login session opened → Valid Accounts
        '5402': 'T1078.003',  # Successful sudo to ROOT → Valid Accounts: Local Accounts

        # 네트워크 탐지
        '20101': 'T1046',  # IDS event
        '533': 'T1049',       # netstat ports changed → System Network Connections Discovery

        # 시스템 탐지
        '510': 'T1082',       # rootcheck anomaly → System Information Discovery
        '502': 'T1082',       # Wazuh server started → System Information Discovery
        '503': 'T1082',       # Wazuh agent started → System Information Discovery

        # SCA (Security Configuration Assessment)
        '19005': 'T1082',     # SCA summary → System Information Discovery
        '19007': 'T1082',     # SCA high severity → System Information Discovery
        '19008': 'T1082',     # SCA medium severity → System Information Discovery
        '19009': 'T1082',     # SCA low severity → System Information Discovery

        # 파일 접근
        '550': 'T1083',       # Integrity checksum changed → File and Directory Discovery
        '554': 'T1083',       # File added to the system → File and Directory Discovery

        # 프로세스
        '592': 'T1059',       # Process creation → Command and Scripting Interpreter
        '594': 'T1059',       # Process execution → Command and Scripting Interpreter
        
        #정찰
        '92604': 'T1057',
        # ========================================
        # BASTION Custom Rules for Caldera Detection
        # ========================================

        # Discovery Techniques (100100-100107)
        '100100': 'T1082',    # System Information Discovery
        '100101': 'T1087',    # User Discovery
        '100102': 'T1057',    # Process Discovery
        '100103': 'T1083',    # File and Directory Discovery
        '100104': 'T1135',    # Network Share Discovery
        '100105': 'T1018',    # Remote System Discovery
        '100106': 'T1018',    # Domain Controller Discovery
        '100107': 'T1518.001', # Security Software Discovery

        # Credential Access (100110-100113)
        '100110': 'T1003.001', # Mimikatz - LSASS Memory
        '100111': 'T1003.001', # LSASS Memory Dump
        '100112': 'T1003.002', # SAM Database Access
        '100113': 'T1552.004', # SSH Key Discovery

        # Lateral Movement (100120-100126)
        '100120': 'T1021.002', # SMB/Admin Shares
        '100121': 'T1021.006', # WinRM
        '100122': 'T1021.004', # SSH Remote Execution
        '100123': 'T1047',     # WMI Remote Execution
        '100124': 'T1569.002', # Remote Service Creation
        '100125': 'T1105',     # Certutil File Transfer
        '100126': 'T1105',     # Esentutl File Copy

        # Collection (100130-100136)
        '100130': 'T1113',     # Screen Capture
        '100131': 'T1115',     # Clipboard Data
        '100132': 'T1123',     # Audio Capture
        '100133': 'T1217',     # Browser Data Collection
        '100134': 'T1083',     # Sensitive File Search
        '100135': 'T1074',     # Data Staging
        '100136': 'T1040',     # Network Sniffing

        # Defense Evasion (100140-100148)
        '100140': 'T1562.001', # Disable Windows Defender
        '100141': 'T1562.004', # Disable Firewall
        '100142': 'T1070.001', # Clear Event Logs
        '100143': 'T1070.001', # Clear Sysmon Logs
        '100144': 'T1562.003', # Disable PowerShell Logging
        '100145': 'T1564.001', # Hidden File Creation
        '100146': 'T1070.004', # Secure File Deletion
        '100147': 'T1036',     # Masquerading
        '100148': 'T1218.011', # Rundll32 Proxy Execution

        # Privilege Escalation (100150-100151)
        '100150': 'T1548.002', # UAC Bypass
        '100151': 'T1548.002', # UAC Bypass via Registry

        # Exfiltration (100160-100161)
        '100160': 'T1567',     # Exfil to Web Service
        '100161': 'T1048.003', # Exfil via FTP

        # Execution (100170-100171)
        '100170': 'T1059.001', # PowerShell Encoded Command
        '100171': 'T1059.001', # PowerShell Download Cradle

        # Persistence (100180-100181)
        '100180': 'T1053.005', # Scheduled Task
        '100181': 'T1547.001', # Registry Run Key

        # WiFi Recon (100190-100191)
        '100190': 'T1016',     # WiFi Network Discovery
        '100191': 'T1552',     # WiFi Password Extraction

        # Linux Specific (100200-100203)
        '100200': 'T1548.003', # Sudo Privilege Enumeration
        '100201': 'T1003.008', # Linux Credential Harvesting
        '100202': 'T1053.003', # Cron Job Persistence
        '100203': 'T1070.003', # History File Tampering

        # Sysmon Rules (100300-100302)
        '100300': 'T1059',     # Suspicious Parent Process
        '100301': 'T1071',     # C2 Port Connection
        '100302': 'T1105',     # Executable in Temp

        # ========================================
        # Auditd Rules for Linux (100400-100460)
        # ========================================

        # Discovery
        '100400': 'T1082',     # System Information via uname
        '100402': 'T1033',     # User Discovery via whoami
        '100403': 'T1033',     # User Discovery via id
        '100404': 'T1087.001', # Local Account Discovery via /etc/passwd
        '100414': 'T1087.001', # Local Account Discovery via getent
        '100405': 'T1016',     # Network Config via arp
        '100415': 'T1016',     # Network Config via ifconfig
        '100416': 'T1016',     # Network Config via ip
        '100406': 'T1049',     # Network Connections via netstat
        '100417': 'T1049',     # Network Connections via ss
        '100407': 'T1057',     # Process Discovery via ps
        '100410': 'T1083',     # File Discovery via find
        '100418': 'T1083',     # File Discovery via ls
        '100419': 'T1083',     # File Discovery via pwd
        '100411': 'T1518',     # Software Discovery via dpkg
        '100412': 'T1518',     # Software Discovery via rpm
        '100413': 'T1518',     # Software Discovery via apt

        # Credential Access
        '100420': 'T1003.008', # /etc/shadow Access

        # Lateral Movement
        '100430': 'T1021.004', # SSH Remote Access
        '100431': 'T1021.004', # SCP File Transfer

        # Command and Control / Ingress
        '100440': 'T1105',     # File Download via curl
        '100441': 'T1105',     # File Download via wget

        # Collection
        '100450': 'T1005',     # Data from Local System via cat
        '100451': 'T1074.001', # Data Staging via mkdir
        '100452': 'T1074.001', # Data Staging via cp
        '100453': 'T1074.001', # Data Staging via mv
        '100454': 'T1074.001', # Data Staging via tar
        '100455': 'T1074.001', # Data Staging via zip
        '100456': 'T1115',     # Clipboard Data via xclip
        '100457': 'T1115',     # Clipboard Data via xsel
    }

    def __init__(self, services: Dict[str, Any], config: Dict[str, Any]):
        """
        Args:
            services: Caldera 서비스 딕셔너리
            config: BASTION 설정
        """
        self.services = services
        self.data_svc = services.get('data_svc')
        self.rest_svc = services.get('rest_svc')
        self.app_svc = services.get('app_svc')
        self.knowledge_svc = services.get('knowledge_svc')
        self.log = self.app_svc.log if self.app_svc else logging.getLogger('bastion')

        # Wazuh 설정
        self.manager_url = config.get('wazuh_manager_url', 'https://localhost:55000')
        self.indexer_url = config.get('wazuh_indexer_url', 'https://localhost:9200')
        self.username = config.get('wazuh_username', 'wazuh')
        self.password = config.get('wazuh_password', 'wazuh')
        self.indexer_username = config.get('indexer_username', 'admin')
        self.indexer_password = config.get('indexer_password', 'SecretPassword')
        # Elasticsearch (Discover 용) - Wazuh Manager 재사용 금지
        self.elastic_url = config.get('elastic_url', 'http://elasticsearch:9200')
        self.elastic_username = config.get('elastic_username', 'elastic')
        self.elastic_password = config.get('elastic_password', 'changeme')
        self.verify_ssl = config.get('verify_ssl', False)
        self.monitor_interval = config.get('alert_query_interval', 300)
        #  IntegrationEngine 초기화
        try:
            self.log.info("[BASTION] IntegrationEngine 초기화 시작...")
            overrides = config.get("integration_engine") or {}
            self.log.info(f"[BASTION] IntegrationEngine overrides: {overrides}")
            # RULE_MITRE_MAPPING을 IntegrationEngine에 전달
            self.integration_engine = IntegrationEngine(overrides, rule_mitre_mapping=self.RULE_MITRE_MAPPING)
            self.log.info("[BASTION] IntegrationEngine 초기화 완료 ✓")
            self.log.info(f"[BASTION] IntegrationEngine client type: {type(self.integration_engine.client).__name__}")
            self.log.info(f"[BASTION] Rule-MITRE 매핑: {len(self.RULE_MITRE_MAPPING)}개 규칙")
        except Exception as e:
            self.integration_engine = None
            self.log.error(f"[BASTION] IntegrationEngine 초기화 실패: {e}")
            import traceback
            traceback.print_exc()

        # 상태 관리
        self.token = None
        self.token_expiry = None
        self.last_alert_time = datetime.utcnow()
        self.is_authenticated = False

        

    async def authenticate(self):
        """Wazuh Manager API 인증"""
        try:
            auth = aiohttp.BasicAuth(self.username, self.password)
            url = f'{self.manager_url}/security/user/authenticate?raw=true'

            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.post(url, auth=auth) as resp:
                    if resp.status == 200:
                        self.token = await resp.text()
                        self.token_expiry = datetime.utcnow() + timedelta(minutes=15)
                        self.is_authenticated = True
                        self.log.info('[BASTION] Wazuh API 인증 성공')
                        return True
                    else:
                        error_text = await resp.text()
                        raise Exception(f'인증 실패 (HTTP {resp.status}): {error_text}')

        except aiohttp.ClientConnectorError as e:
            self.log.error(f'[BASTION] Wazuh Manager 연결 실패: {e}')
            self.log.error(f'[BASTION] {self.manager_url} 주소가 올바른지 확인하세요')
            raise
        except asyncio.TimeoutError:
            self.log.error('[BASTION] Wazuh API 연결 타임아웃 (10초)')
            raise
        except Exception as e:
            self.log.error(f'[BASTION] Wazuh 인증 오류: {e}')
            raise

    # -----------------------------
    # Elasticsearch (Discover 용)
    # -----------------------------
    async def get_es_indices(self, request: web.Request) -> web.Response:
        """
        Elasticsearch 인덱스 목록 반환 (Discover용)
        """
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            auth = aiohttp.BasicAuth(self.elastic_username, self.elastic_password)
            url = f'{self.elastic_url}/_cat/indices?format=json&h=index'

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.get(url, auth=auth) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        raise Exception(f'ES indices 호출 실패 (HTTP {resp.status}): {text}')
                    data = await resp.json()
                    indices = [item.get('index') for item in data if item.get('index')]
                    # 중복 제거 + 정렬
                    unique = sorted(set(indices))
                    return web.json_response(unique)
        except Exception as e:
            self.log.error(f'[BASTION] ES 인덱스 조회 실패: {e}')
            return web.json_response({'error': str(e)}, status=500)

    async def search_es(self, request: web.Request) -> web.Response:
        """
        Elasticsearch 검색 프록시 (Discover용)
        Body: { index, kql, timeRange:{from,to}, filters:[{field,operator,value}] }
        """
        try:
            payload = await request.json()
            index = payload.get('index') or '*'
            kql = payload.get('kql') or ''
            time_range = payload.get('timeRange') or {}
            filters = payload.get('filters') or []

            query = self._build_es_query(kql, time_range, filters)
            body = {
                'query': query,
                'size': 200,
                'sort': [
                    {'@timestamp': {'order': 'desc'}}
                ]
            }

            timeout = aiohttp.ClientTimeout(total=20)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            auth = aiohttp.BasicAuth(self.elastic_username, self.elastic_password)
            url = f'{self.elastic_url}/{index}/_search'

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.post(url, auth=auth, json=body) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        raise Exception(f'ES search 실패 (HTTP {resp.status}): {text}')
                    data = await resp.json()
                    hits = data.get('hits', {}).get('hits', [])
                    rows = []
                    columns = set()
                    for hit in hits:
                        source = hit.get('_source', {}) or {}
                        doc_id = hit.get('_id')
                        if doc_id:
                            source['id'] = doc_id
                        rows.append(source)
                        columns.update(source.keys())
                    columns = sorted(list(columns))
                    result = {
                        'total': data.get('hits', {}).get('total', {}).get('value', len(rows)),
                        'columns': columns,
                        'rows': rows
                    }
                    return web.json_response(result)
        except Exception as e:
            self.log.error(f'[BASTION] ES 검색 실패: {e}')
            return web.json_response({'error': str(e)}, status=500)

    def _build_es_query(self, kql: str, time_range: Dict[str, str], filters: List[Dict[str, str]]):
        """
        키바나 KQL을 단순 query_string으로 래핑하고, 필드 필터/시간 범위를 bool.must에 추가
        """
        must_clauses = []
        must_not_clauses = []

        # KQL -> query_string (간단 위임)
        if kql:
            must_clauses.append({
                'query_string': {
                    'query': kql
                }
            })

        # 시간 범위 (@timestamp 기준)
        time_from = (time_range or {}).get('from')
        time_to = (time_range or {}).get('to')
        if time_from or time_to:
            range_query = {'range': {'@timestamp': {}}}
            if time_from:
                range_query['range']['@timestamp']['gte'] = time_from
            if time_to:
                range_query['range']['@timestamp']['lte'] = time_to
            must_clauses.append(range_query)

        # 필드 필터
        for f in filters or []:
            field = f.get('field')
            op = (f.get('operator') or '').lower()
            value = f.get('value')
            if not field or value is None:
                continue
            if op == 'is not':
                must_not_clauses.append({'term': {field: value}})
            elif op == 'contains':
                must_clauses.append({'wildcard': {field: f'*{value}*'}})
            else:  # default 'is'
                must_clauses.append({'term': {field: value}})

        return {
            'bool': {
                'must': must_clauses or [{'match_all': {}}],
                'must_not': must_not_clauses
            }
        }

    # -----------------------------
    # Discover API (MVP)
    # -----------------------------
    async def get_discover_indices(self, request: web.Request) -> web.Response:
        """GET /api/discover/indices - Elasticsearch _cat/indices"""
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            auth = aiohttp.BasicAuth(self.elastic_username, self.elastic_password)
            url = f'{self.elastic_url}/_cat/indices?format=json'
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.get(url, auth=auth) as resp:
                    text = await resp.text()
                    if resp.status == 401:
                        return web.json_response({'error': 'Elasticsearch 인증 실패'}, status=401)
                    if resp.status != 200:
                        raise Exception(f'ES indices 호출 실패 (HTTP {resp.status}): {text}')
                    try:
                        data = json.loads(text)
                    except Exception:
                        data = []
                    indices = [item.get('index') for item in data if item.get('index')]
                    return web.json_response(indices)
        except (asyncio.TimeoutError, aiohttp.ClientError) as e:
            self.log.error(f'[Discover] 인덱스 조회 타임아웃/클라이언트 오류: {e}')
            return web.json_response({'error': 'Elasticsearch 요청 실패'}, status=504)
        except Exception as e:
            self.log.error(f'[Discover] 인덱스 조회 실패: {e}')
            return web.json_response({'error': str(e)}, status=500)

    async def discover_search(self, request: web.Request) -> web.Response:
        """
        POST /api/discover/search
        Body: { index, from, to, query, size }
        Query DSL: bool + query_string + range @timestamp
        """
        try:
            payload = await request.json()
            index = payload.get('index') or '*'
            q_from = payload.get('from')
            q_to = payload.get('to')
            query_text = payload.get('query') or '*'
            size = int(payload.get('size') or 50)
            offset = int(payload.get('offset') or 0)

            must = [{
                'query_string': {
                    'query': query_text
                }
            }]
            filters = []
            if q_from or q_to:
                ts = {}
                if q_from:
                    ts['gte'] = q_from
                if q_to:
                    ts['lte'] = q_to
                filters.append({'range': {'@timestamp': ts}})

            body = {
                'query': {
                    'bool': {
                        'must': must,
                        'filter': filters
                    }
                },
                'sort': [{'@timestamp': {'order': 'desc'}}],
                'size': size
            }
            if offset > 0:
                body['from'] = offset

            timeout = aiohttp.ClientTimeout(total=20)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            auth = aiohttp.BasicAuth(self.elastic_username, self.elastic_password)
            search_url = f'{self.elastic_url}/{index}/_search'
            field_caps_url = f'{self.elastic_url}/{index}/_field_caps?fields=*'

            # Collect field names from field_caps for complete schema coverage
            fields_from_caps = set()
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                try:
                    async with session.get(field_caps_url, auth=auth) as resp:
                        if resp.status == 200:
                            caps_data = await resp.json()
                            fields_dict = caps_data.get('fields', {}) or {}
                            fields_from_caps.update(fields_dict.keys())
                        else:
                            self.log.warning(f'[Discover] field_caps fallback (HTTP {resp.status})')
                except Exception as caps_err:
                    self.log.warning(f'[Discover] field_caps fetch failed: {caps_err}')

                async with session.post(search_url, auth=auth, json=body) as resp:
                    text = await resp.text()
                    if resp.status == 401:
                        return web.json_response({'error': 'Elasticsearch 인증 실패'}, status=401)
                    if resp.status != 200:
                        raise Exception(f'ES search 실패 (HTTP {resp.status}): {text}')
                    try:
                        data = json.loads(text)
                    except Exception:
                        data = {}
                    hits = data.get('hits', {}).get('hits', [])
                    rows = []
                    columns = set()

                    def flatten_keys(obj, prefix=''):
                        keys = []
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                path = f'{prefix}.{k}' if prefix else k
                                keys.append(path)
                                if isinstance(v, dict):
                                    keys.extend(flatten_keys(v, path))
                                elif isinstance(v, list):
                                    for item in v:
                                        if isinstance(item, dict):
                                            keys.extend(flatten_keys(item, path))
                        elif isinstance(obj, list):
                            for item in obj:
                                if isinstance(item, dict):
                                    keys.extend(flatten_keys(item, prefix))
                        return keys

                    for hit in hits:
                        source = hit.get('_source', {}) or {}
                        doc_id = hit.get('_id')
                        if doc_id:
                            source['id'] = doc_id
                        rows.append(source)
                        columns.update(flatten_keys(source))

                    used_fields = set(columns)
                    all_fields = fields_from_caps or used_fields
                    available_fields = used_fields
                    empty_fields = set(all_fields) - used_fields

                    columns_sorted = sorted(list(available_fields))
                    result = {
                        'total': data.get('hits', {}).get('total', {}).get('value', len(rows)),
                        'columns': columns_sorted,
                        'fields': {
                            'available': sorted(list(available_fields)),
                            'empty': sorted(list(empty_fields))
                        },
                        'rows': rows
                    }
                    return web.json_response(result)
        except (asyncio.TimeoutError, aiohttp.ClientError) as e:
            self.log.error(f'[Discover] 검색 타임아웃/클라이언트 오류: {e}')
            return web.json_response({'error': 'Elasticsearch 요청 실패'}, status=504)
        except Exception as e:
            self.log.error(f'[Discover] 검색 실패: {e}')
            return web.json_response({'error': str(e)}, status=500)

    async def _ensure_authenticated(self):
        """토큰 유효성 확인 및 재인증"""
        if not self.token or not self.token_expiry:
            await self.authenticate()
        elif datetime.utcnow() >= self.token_expiry:
            self.log.info('[BASTION] 토큰 만료, 재인증 중...')
            await self.authenticate()

    async def get_recent_alerts(self, request: web.Request) -> web.Response:
        """
        최근 Wazuh 알림 조회

        Query Parameters:
            hours: 조회 시간 범위 (기본: 1시간)
            min_level: 최소 심각도 레벨 (기본: 7)
        """
        try:
            hours = int(request.query.get('hours', 1))
            min_level = int(request.query.get('min_level', 7))

            self.log.info(f'[BASTION] 알림 조회 요청: 최근 {hours}시간, 레벨 >= {min_level}')

            # OpenSearch 쿼리
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": min_level}}},
                            {"range": {"timestamp": {"gte": f"now-{hours}h"}}}
                        ]
                    }
                },
                "size": 100,
                "sort": [{"timestamp": {"order": "desc"}}],
                "_source": [
                "@timestamp","timestamp",
                "rule.id", "rule.level", "rule.description",
                "agent.id", "agent.name",
                "data.mitre", "data.mitre.id", "data.mitre.tactic",
                "rule.mitre.technique", "rule.mitre.id",
                ]
            }

            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                # Wazuh Indexer 인증
                auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                async with session.post(
                    f'{self.indexer_url}/wazuh-alerts-*/_search',
                    json=query,
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        alerts = data.get('hits', {}).get('hits', [])

                        # MITRE 기법 추출 및 각 alert에 technique_id 추가
                        techniques = set()
                        processed_alerts = []

                        for alert in alerts:
                            source = alert.get('_source', {})
                            

                            # 1. 먼저 알림에서 직접 MITRE 데이터 확인
                            # rule.mitre.id 필드에서 기술 ID 추출
                            rule_data = source.get('rule', {})
                            mitre_data = rule_data.get('mitre', {})
                            technique_id = None

                            if isinstance(mitre_data, dict) and 'id' in mitre_data:
                                # mitre.id는 배열일 수 있으므로 첫 번째 값 사용
                                mitre_ids = mitre_data['id']
                                if isinstance(mitre_ids, list) and len(mitre_ids) > 0:
                                    technique_id = mitre_ids[0]
                                elif isinstance(mitre_ids, str):
                                    technique_id = mitre_ids

                            # 2. MITRE 데이터가 없으면 규칙 ID 매핑 테이블 사용
                            if not technique_id:
                                rule_id = str(rule_data.get('id', ''))
                                technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                            if technique_id:
                                techniques.add(technique_id)

                            # 각 alert에 매핑된 technique_id 추가 (프론트엔드 표시용)
                            alert_data = source.copy()
                            alert_data['technique_id'] = technique_id
                            processed_alerts.append(alert_data)

                        result = {
                            'success': True,
                            'total': len(alerts),
                            'alerts': processed_alerts,
                            'detected_techniques': list(techniques),
                            'query_time': datetime.utcnow().isoformat()
                        }

                        self.log.info(f'[BASTION] 알림 {len(alerts)}건 조회 완료')
                        return web.json_response(result)
                    else:
                        error_text = await resp.text()
                        self.log.error(f'[BASTION] Indexer 쿼리 실패: {error_text}')
                        return web.json_response({
                            'success': False,
                            'error': f'Indexer query failed: HTTP {resp.status}'
                        }, status=500)

        except Exception as e:
            self.log.error(f'[BASTION] 알림 조회 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def correlate_operation(self, request: web.Request) -> web.Response:
        """
        Caldera 작전과 Wazuh 알림 상관관계 분석
        (IntegrationEngine 기반으로 operation ↔ detection 매칭)
        """
        try:
            if not hasattr(self, 'integration_engine') or self.integration_engine is None:
                return web.json_response({
                    'success': False,
                    'error': 'IntegrationEngine not initialized'
                }, status=500)

            data = await request.json()
            operation_id = data.get('operation_id')

            if not operation_id:
                return web.json_response({
                    'success': False,
                    'error': 'operation_id required'
                }, status=400)

            # 1) Caldera 작전 조회
            operations = await self.data_svc.locate('operations', match={'id': operation_id})
            if not operations:
                return web.json_response({
                    'success': False,
                    'error': f'Operation {operation_id} not found'
                }, status=404)

            operation = operations[0]

            # 2) 작전 실행 시간 범위 계산 (안전한 timezone 처리)
            start_time = operation.start
            if start_time:
                if hasattr(start_time, 'tzinfo') and start_time.tzinfo:
                    start_time = start_time.replace(tzinfo=None)
            else:
                start_time = datetime.utcnow()

            end_time = operation.finish if operation.finish else datetime.utcnow()
            if end_time:
                if hasattr(end_time, 'tzinfo') and end_time.tzinfo:
                    end_time = end_time.replace(tzinfo=None)

            try:
                duration_seconds = int((end_time - start_time).total_seconds())
            except Exception as e:
                self.log.debug(f'[BASTION] duration 계산 실패: {e}')
                duration_seconds = 0

            # 3) 작전에서 실행된 MITRE 기법 & ability 목록 구성 (안전한 처리)
            operation_techniques = set()
            executed_abilities = []

            for link in operation.chain:
                try:
                    ability = getattr(link, 'ability', None)
                    if not ability:
                        continue

                    ability_data = {
                        'ability_id': getattr(ability, 'ability_id', ''),
                        'name': getattr(ability, 'name', ''),
                        'tactic': getattr(ability, 'tactic', ''),
                        'technique_id': getattr(ability, 'technique_id', ''),
                        'technique_name': getattr(ability, 'technique_name', '')
                    }
                    executed_abilities.append(ability_data)

                    if ability_data.get('technique_id'):
                        operation_techniques.add(ability_data['technique_id'])
                except Exception as link_err:
                    self.log.debug(f'[BASTION] 링크 처리 중 에러 (skip): {link_err}')
                    continue

            self.log.info(f'[BASTION] 작전 실행 기법: {operation_techniques}')

            # 4) 🔹 IntegrationEngine을 이용해 링크별 탐지 매칭
            #    conf/default.yml에 설정된 index, time_window_sec, 필드 매핑들을 사용
            link_results = []
            try:
                link_results = await self.integration_engine.correlate(operation)
            except Exception as corr_err:
                self.log.error(f'[BASTION] IntegrationEngine correlate 실패: {corr_err}')
                return web.json_response({
                    'success': False,
                    'error': f'Correlation failed: {str(corr_err)}'
                }, status=500)
            # link_results 각 원소 예시:
            # {
            #   'link_id': '...',
            #   'ability_name': '...',
            #   'technique_id': 'T1059',
            #   'executed_at': '2025-11-18T05:10:33Z',
            #   'detected': True/False,
            #   'match_count': N,
            #   'matches': [
            #       {
            #         '@timestamp': '2025-11-18T05:10:35Z',
            #         'rule.id': '592',
            #         'level': 5,
            #         'mitre.id': 'T1059',
            #         'agent.id': '001',
            #         'agent.name': 'victim-linux-1',
            #         'description': 'Process creation',
            #         'full.log': '...'
            #       }, ...
            #   ]
            # }

            # 5) 탐지된 Technique / 매칭된 alert 리스트 계산 (안전한 처리)
            detected_techniques = set()
            alerts_matched = []

            for lr in link_results:
                try:
                    tech = lr.get('technique_id')
                    if tech and lr.get('detected'):
                        detected_techniques.add(tech)

                    link_id = lr.get('link_id', '')
                    ability_name = lr.get('ability_name', '')

                    for m in lr.get('matches', []):
                        try:
                            alerts_matched.append({
                                # Vue 테이블에서 쓰기 좋은 형태로 필드명 정리
                                'timestamp': m.get('@timestamp') or m.get('timestamp'),
                                'rule_id': m.get('rule.id') or m.get('rule_id'),
                                'rule_level': m.get('level') or m.get('rule_level'),
                                'description': m.get('description', ''),
                                'agent_name': m.get('agent.name') or m.get('agent_name'),
                                'agent_id': m.get('agent.id') or m.get('agent_id'),
                                'technique_id': tech or m.get('mitre.id') or m.get('technique_id'),
                                # 어느 링크/ability에서 나온 탐지인지도 같이 제공
                                'link_id': link_id,
                                'ability_name': ability_name,
                                'match_status': 'MATCHED',
                                'match_source': 'wazuh'
                            })
                        except Exception as alert_err:
                            self.log.debug(f'[BASTION] 알림 처리 중 에러 (skip): {alert_err}')
                            continue
                except Exception as lr_err:
                    self.log.debug(f'[BASTION] link_result 처리 중 에러 (skip): {lr_err}')
                    continue

            # 6) 매칭 및 탐지율 계산 (기존 구조 그대로)
            matched_techniques = operation_techniques.intersection(detected_techniques)
            undetected_techniques = operation_techniques - detected_techniques

            detection_rate = 0.0
            if operation_techniques:
                detection_rate = len(matched_techniques) / len(operation_techniques)

            # 7) 최종 상관관계 결과 생성 (기존 response schema 유지 + links 추가)
            correlation_result = {
                'success': True,
                'operation_id': operation_id,
                'operation_name': operation.name,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration_seconds,
                'correlation': {
                    'detection_rate': round(detection_rate, 2),
                    'total_techniques': len(operation_techniques),
                    'detected_techniques': len(matched_techniques),
                    'undetected_techniques': len(undetected_techniques),
                    'matched_techniques': list(matched_techniques),
                    'undetected_techniques_list': list(undetected_techniques),
                    'all_operation_techniques': list(operation_techniques),
                    'all_detected_techniques': list(detected_techniques)
                },
                'executed_abilities': executed_abilities,
                # 🔹 link별 raw 결과도 내려주면 프론트에서 더 디테일하게 쓸 수 있음
                'links': link_results,
                # 🔹 기존 alerts_matched도 그대로 유지 (Vue Detection Table 용)
                'alerts_matched': alerts_matched,
                'total_alerts': len(alerts_matched)
            }

            self.log.info(
                f'[BASTION] 상관관계 분석 완료 (IntegrationEngine): '
                f'탐지율 {detection_rate:.1%}, links={len(link_results)}, alerts={len(alerts_matched)}'
            )

            return web.json_response(correlation_result)

        except Exception as e:
            self.log.error(f'[BASTION] 상관관계 분석 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)


    async def generate_detection_report(self, request: web.Request) -> web.Response:
        """탐지 커버리지 리포트 생성"""
        try:
            # TODO: 구현 필요
            report = {
                'success': True,
                'message': 'Detection report generation not implemented yet',
                'total_operations': 0,
                'detection_rate': 0.0
            }

            return web.json_response(report)

        except Exception as e:
            self.log.error(f'[BASTION] 리포트 생성 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def create_adaptive_operation(self, request: web.Request) -> web.Response:
        """Wazuh 데이터 기반 적응형 작전 생성"""
        try:
            # TODO: 구현 필요
            return web.json_response({
                'success': True,
                'message': 'Adaptive operation not implemented yet'
            })

        except Exception as e:
            self.log.error(f'[BASTION] 적응형 작전 생성 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def get_agents_with_detections(self, request: web.Request) -> web.Response:
        """
        Caldera Agents 목록 + Wazuh Agent 매칭 + 최근 탐지 정보

        Query Parameters:
            hours: 조회 시간 범위 (기본: 1시간)
            operation_id: 특정 작전 ID 필터 (선택사항)
            os_filter: OS 플랫폼 필터 (선택사항: Windows, Linux, macOS)
            search: 검색어 (선택사항)
        """
        try:
            hours = int(request.query.get('hours', 24))
            operation_id_filter = request.query.get('operation_id', '').strip()
            raw_os = request.query.get('os_filter') or request.query.get('os')
            os_filter = (raw_os or '').strip().lower()
            search_query = request.query.get('search', '').strip().lower()

            self.log.info(f'[BASTION] Agents 조회 요청 (최근 {hours}시간 탐지, op_filter={operation_id_filter}, os={os_filter}, search={search_query})')

            # 1. Wazuh Agents 조회 (ID로 인덱싱)
            wazuh_agents_by_id = {}
            wazuh_agents_by_name = {}
            try:
                await self._ensure_authenticated()
                timeout = aiohttp.ClientTimeout(total=10)
                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    headers = {'Authorization': f'Bearer {self.token}'}
                    async with session.get(f'{self.manager_url}/agents', headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for wazuh_agent in data.get('data', {}).get('affected_items', []):
                                agent_id = wazuh_agent.get('id')
                                wazuh_agents_by_id[agent_id] = {
                                    'id': agent_id,
                                    'name': wazuh_agent.get('name', ''),
                                    'ip': wazuh_agent.get('ip'),
                                    'status': wazuh_agent.get('status'),
                                    'version': wazuh_agent.get('version')
                                }
                                name_key = (wazuh_agent.get('name') or '').lower()
                                if name_key: 
                                   wazuh_agents_by_name[name_key] = wazuh_agents_by_id[agent_id] 
                            self.log.info(f'[BASTION] Agents {len(wazuh_agents_by_id)}개 조회')
            except Exception as e:
                self.log.warning(f'[BASTION] Agents 조회 실패: {e}')

            # 2. Caldera Agents 조회
            agents = await self.data_svc.locate('agents')

            agents_data = []
            for agent in agents:
                # Agent alive 상태 판단 (timezone 안전)
                alive = False
                if agent.last_seen:
                    try:
                        # timezone-aware datetime 처리
                        last_seen = agent.last_seen.replace(tzinfo=None) if agent.last_seen.tzinfo else agent.last_seen
                        alive = (datetime.utcnow() - last_seen).total_seconds() < 300  # 5분 이내
                    except Exception as e:
                        self.log.debug(f'[BASTION] Agent {agent.paw} alive 상태 계산 실패: {e}')
                        alive = False

                # last_seen 처리 (datetime 또는 str)
                last_seen = None
                if agent.last_seen:
                    last_seen = agent.last_seen.isoformat() if isinstance(agent.last_seen, datetime) else agent.last_seen

                agent_info = {
                    'paw': agent.paw,
                    'host': agent.host,
                    'username': agent.username,
                    'platform': agent.platform,
                    'executors': agent.executors,
                    'privilege': agent.privilege,
                    'last_seen': last_seen,
                    'sleep_min': agent.sleep_min,
                    'sleep_max': agent.sleep_max,
                    'group': agent.group,
                    'contact': agent.contact,
                    'alive': alive,
                    'recent_detections': [],
                    'attack_steps_count': 0,  # Week 11: Agent별 attack steps 수
                    'detections_count': 0     # Week 11: Agent별 detections 수
                }

                # Wazuh Agent 매칭
                wazuh_agent = None
                wazuh_agent_id = None

                # 1) 우선: Agent links의 facts에서 wazuh.agent.id 찾기
                try:
                    if hasattr(agent, 'links') and agent.links:
                        for link in agent.links:
                            if hasattr(link, 'facts') and link.facts:
                                for fact in link.facts:
                                    if fact.trait == 'wazuh.agent.id':
                                        wazuh_agent_id = str(fact.value).strip()
                                        self.log.info(
                                            f'[BASTION] Agent {agent.paw}: '
                                            f'Wazuh ID {wazuh_agent_id} (links에서 발견)'
                                        )
                                        break
                            if wazuh_agent_id:
                                break
                except Exception as e:
                    self.log.error(f'[BASTION] Error getting facts for agent {agent.paw}: {e}')

                # 2) Fallback: Caldera agent.host == Wazuh agent.name 이면 매핑
                if not wazuh_agent_id and agent.host:
                    host_key = (agent.host or '').lower()
                    fallback = wazuh_agents_by_name.get(host_key)
                    if fallback:
                        wazuh_agent_id = fallback.get('id')
                        self.log.info(
                            f'[BASTION DEBUG] Agent {agent.paw}: '
                            f'host="{agent.host}" 기반 Wazuh 매핑 → '
                            f'{wazuh_agent_id} ({fallback.get("name")})'
                        )

                # 3) 둘 다 실패하면 경고만 남김
                if not wazuh_agent_id:
                    self.log.warning(
                        f'[BASTION DEBUG] Agent {agent.paw}: '
                        f'Wazuh 매핑 실패 (facts/host 모두 불일치)'
                    )


                # Wazuh agent 정보 조회
                if wazuh_agent_id:
                    wazuh_agent = wazuh_agents_by_id.get(wazuh_agent_id)
                    if not wazuh_agent:
                        self.log.warning(f'[BASTION] Agent {agent.paw}: Wazuh ID {wazuh_agent_id} 존재하지 않음')

                agent_info['wazuh_matched'] = wazuh_agent is not None
                agent_info['wazuh_agent'] = wazuh_agent if wazuh_agent else None

                # 2. 각 Agent의 최근 Wazuh 탐지 조회 (매칭된 경우만)
                if wazuh_agent:
                    query = {
                        "query": {
                            "bool": {
                                "must": [
                                    {"range": {"rule.level": {"gte": 5}}},
                                    {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
                                    {"term": {"agent.id": wazuh_agent['id']}}
                                ]
                            }
                        },
                        "size": 10,
                        "sort": [{"timestamp": {"order": "desc"}}],
                        "_source": [
                        "@timestamp", "timestamp",
                        "rule.id", "rule.level", "rule.description",
                        "data.mitre", "data.mitre.id", "data.mitre.tactic",
                        "rule.mitre.technique", "rule.mitre.id",
                        "agent.name", "agent.ip"
                        ]
                    }

                    try:
                        timeout = aiohttp.ClientTimeout(total=10)
                        connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

                        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                            auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                            async with session.post(
                                f'{self.indexer_url}/wazuh-alerts-*/_search',
                                json=query,
                                auth=auth
                            ) as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    alerts = data.get('hits', {}).get('hits', [])

                                    for alert in alerts:
                                        source = alert.get('_source', {})

                                        # 1. 먼저 알림에서 직접 MITRE 데이터 확인
                                        mitre_data = source.get('data', {}).get('mitre', {})
                                        technique_id = mitre_data.get('id') if isinstance(mitre_data, dict) else None

                                        # 2. MITRE 데이터가 없으면 규칙 ID 매핑 테이블 사용
                                        if not technique_id:
                                            rule_id = str(source.get('rule', {}).get('id', ''))
                                            technique_id = self.RULE_MITRE_MAPPING.get(rule_id)
                                        
                                        ts = source.get('@timestamp') or source.get('timestamp')
                                        agent_info['recent_detections'].append({
                                            'timestamp': ts,
                                            'rule_id': source.get('rule', {}).get('id'),
                                            'rule_level': source.get('rule', {}).get('level'),
                                            'description': source.get('rule', {}).get('description'),
                                            'technique_id': technique_id
                                        })

                    except Exception as e:
                        self.log.warning(f'[BASTION] Agent {agent.paw} 탐지 조회 실패: {e}')
                        # 에러가 나도 agent 정보는 반환

                # 1. Detections count - IntegrationEngine으로 매칭된 탐지만 카운트
                matched_detections_count = 0

                # IntegrationEngine을 사용해서 이 agent의 매칭된 탐지 카운트
                if hasattr(self, 'integration_engine') and self.integration_engine:
                    try:
                        # 최근 operation들에 대해 correlation 수행
                        all_operations = await self.data_svc.locate('operations')
                        cutoff_time = datetime.utcnow() - timedelta(hours=hours)

                        for op in all_operations:
                            # operation_id_filter가 있으면 해당 operation만
                            if operation_id_filter and op.id != operation_id_filter:
                                continue

                            # 시간 범위 체크
                            if op.start:
                                op_start = op.start.replace(tzinfo=None) if op.start.tzinfo else op.start
                                if isinstance(op_start, datetime) and op_start < cutoff_time:
                                    continue

                            # IntegrationEngine correlation 수행
                            try:
                                link_results = await self.integration_engine.correlate(op)

                                # 이 agent의 link 중 detected=True인 것만 카운트
                                for link_result in link_results:
                                    link_paw = link_result.get('paw')
                                    detected = link_result.get('detected', False)

                                    if link_paw == agent.paw and detected:
                                        matched_detections_count += 1
                            except Exception as corr_err:
                                self.log.debug(f"[BASTION] Agent {agent.paw} correlation 실패: {corr_err}")
                                continue
                    except Exception as e:
                        self.log.warning(f"[BASTION] Agent {agent.paw} 매칭 탐지 카운트 실패: {e}")

                agent_info['detections_count'] = matched_detections_count

                # 2. Attack steps count - operations에서 직접 계산
                try:
                    attack_steps_count = 0
                    all_operations = await self.data_svc.locate('operations')
                    cutoff_time = datetime.utcnow() - timedelta(hours=hours)

                    for op in all_operations:
                        # operation_id_filter가 있으면 해당 operation만
                        if operation_id_filter and op.id != operation_id_filter:
                            continue

                        # 시간 범위 체크
                        if op.start:
                            op_start = op.start.replace(tzinfo=None) if op.start.tzinfo else op.start
                            if isinstance(op_start, datetime) and op_start < cutoff_time:
                                continue

                        # 이 agent의 links 카운트
                        for link in op.chain:
                            if hasattr(link, 'paw') and link.paw == agent.paw and link.finish:
                                attack_steps_count += 1

                    agent_info['attack_steps_count'] = attack_steps_count
                except Exception as e:
                    self.log.warning(f'[BASTION] Agent {agent.paw} attack steps 계산 실패: {e}')

                # OS Filter 적용
                if os_filter:
                    platform = (agent.platform or '').lower()
                    self.log.debug(
                        f'[BASTION DEBUG] OS filter check: agent={agent.paw}, '
                        f'platform="{platform}", os_filter="{os_filter}"'
                    )
                    if os_filter not in platform:
                        continue

                # Search Filter 적용
                if search_query:
                    search_match = False
                    if search_query in agent.paw.lower():
                        search_match = True
                    elif search_query in (agent.host or '').lower():
                        search_match = True
                    elif search_query in (agent.username or '').lower():
                        search_match = True
                    if not search_match:
                        continue

                # Operation Filter 적용 (해당 작전에 참여한 agent만 포함)
                if operation_id_filter:
                    all_operations = await self.data_svc.locate('operations')
                    operation_match = False
                    for op in all_operations:
                        if op.id == operation_id_filter:
                            # 이 작전의 agent 중에 현재 agent가 있는지 확인
                            for op_agent in op.agents:
                                if op_agent.paw == agent.paw:
                                    operation_match = True
                                    break
                            break
                    if not operation_match:
                        continue

                agents_data.append(agent_info)

            result = {
                'success': True,
                'total_agents': len(agents_data),
                'agents': agents_data,
                'query_time': datetime.utcnow().isoformat()
            }

            self.log.info(f'[BASTION] Agents {len(agents_data)}개 조회 완료')
            return web.json_response(result)

        except Exception as e:
            self.log.error(f'[BASTION] Agents 조회 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def health_check(self, request: web.Request) -> web.Response:
        """플러그인 및 Wazuh 연결 상태 확인"""
        try:
            health = {
                'plugin': 'healthy',
                'wazuh_manager': 'unknown',
                'wazuh_indexer': 'unknown',
                'authenticated': self.is_authenticated,
                'timestamp': datetime.utcnow().isoformat()
            }

            # Wazuh Manager 상태 확인
            try:
                await self._ensure_authenticated()
                health['wazuh_manager'] = 'healthy'
            except Exception as e:
                health['wazuh_manager'] = f'unhealthy: {str(e)}'

            # Wazuh Indexer 상태 확인
            try:
                timeout = aiohttp.ClientTimeout(total=5)
                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                    async with session.get(f'{self.indexer_url}/_cluster/health', auth=auth) as resp:
                        if resp.status == 200:
                            cluster_health = await resp.json()
                            health['wazuh_indexer'] = cluster_health.get('status', 'unknown')
            except Exception as e:
                health['wazuh_indexer'] = f'unhealthy: {str(e)}'

            return web.json_response(health)

        except Exception as e:
            self.log.error(f'[BASTION] 헬스체크 실패: {e}', exc_info=True)
            return web.json_response({
                'plugin': 'unhealthy',
                'error': str(e)
            }, status=500)

    async def get_dashboard_summary(self, request: web.Request) -> web.Response:
        """
        대시보드 통합 데이터 조회 (KPI, Operations, Tactic Coverage, Timeline)

        Query Parameters:
            hours: 조회 시간 범위 (기본: 24시간)
            min_level: 최소 심각도 레벨 (기본: 5)
            operation_id: 특정 작전 ID 필터 (선택사항)
            os_filter: OS 플랫폼 필터 (선택사항: Windows, Linux, macOS)
            search: 검색어 (선택사항)
        """
        try:
            hours = int(request.query.get('hours', 24))
            min_level = int(request.query.get('min_level', 5))
            operation_id_filter = request.query.get('operation_id', '').strip()
            raw_os = request.query.get('os_filter') or request.query.get('os')
            os_filter = (raw_os or '').strip().lower()
            search_query = request.query.get('search', '').strip().lower()

            self.log.info(
                f'[BASTION] 대시보드 요약 조회: 최근 {hours}시간 '
                f'(op_filter={operation_id_filter}, os_filter={os_filter}, search={search_query})'
            )

            # 1. Operations 목록 조회 (Caldera)
            all_operations = await self.data_svc.locate('operations')
            all_agents = await self.data_svc.locate('agents')  # 모든 agents 조회

            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            operations_data = []
            filtered_ops: List[Any] = []
            total_attack_steps = 0
            operation_techniques = set()  # 전체 작전에서 실행된 기법

            self.log.debug(
                f'[BASTION DEBUG] Total operations: {len(all_operations)}, cutoff_time: {cutoff_time}'
            )

            for op in all_operations:
                # 1) Operation ID 필터
                if operation_id_filter and op.id != operation_id_filter:
                    continue

                # 2) 시간 필터: operation_id_filter가 없을 때만 적용
                include_by_time = True
                op_start = None

                if not operation_id_filter and op.start:
                    op_start = op.start.replace(tzinfo=None) if op.start.tzinfo else op.start
                    if isinstance(op_start, datetime) and op_start < cutoff_time:
                        include_by_time = False

                if not include_by_time:
                    continue

                # 3) 작전 실행 단계 추출
                attack_steps = []
                op_techniques = set()

                for link in op.chain:
                    ability = link.ability
                    # link.finish가 datetime 객체인 경우 isoformat 변환, 문자열인 경우 그대로 사용
                    finish_time = None
                    if link.finish:
                        if isinstance(link.finish, str):
                            finish_time = link.finish
                        else:
                            finish_time = link.finish.isoformat()

                    attack_steps.append({
                        'ability_id': ability.ability_id,
                        'name': ability.name,
                        'tactic': ability.tactic,
                        'technique_id': ability.technique_id,
                        'technique_name': ability.technique_name,
                        'timestamp': finish_time,
                        'paw': link.paw  # Agent ID 추가 (OS filter용)
                    })

                    if ability.technique_id:
                        op_techniques.add(ability.technique_id)
                        operation_techniques.add(ability.technique_id)

                total_attack_steps += len(attack_steps)

                # Agent PAWs와 platforms 매핑
                agent_paws = []
                agent_platforms = {}

                # attack_steps의 모든 PAW를 먼저 수집
                attack_step_paws = set(step['paw'] for step in attack_steps)
                self.log.warning(
                    f'[BASTION DEBUG] Operation {op.name}: attack_step_paws = {attack_step_paws}'
                )

                # 각 PAW의 platform을 all_agents 또는 op.agents/chain에서 찾기
                for paw in attack_step_paws:
                    found = False

                    # 1. all_agents에서 찾기
                    for agent in all_agents:
                        if agent.paw == paw:
                            agent_platforms[paw] = agent.platform
                            agent_paws.append(paw)
                            found = True
                            break

                    # 2. op.agents에서 찾기 (all_agents에 없는 경우)
                    if not found:
                        for agent in op.agents:
                            if agent.paw == paw:
                                agent_platforms[paw] = agent.platform
                                agent_paws.append(paw)
                                found = True
                                break

                    # 3. executor로 platform 유추
                    if not found:
                        for link in op.chain:
                            if link.paw == paw and link.executor:
                                executor_name = link.executor.name
                                if executor_name in ['sh', 'bash']:
                                    agent_platforms[paw] = 'linux'
                                elif executor_name in ['cmd', 'psh', 'powershell']:
                                    agent_platforms[paw] = 'windows'
                                elif executor_name == 'osascript':
                                    agent_platforms[paw] = 'darwin'
                                else:
                                    agent_platforms[paw] = 'linux'
                                agent_paws.append(paw)
                                self.log.warning(
                                    f'[BASTION DEBUG] Inferred {paw} from executor '
                                    f'{executor_name}: {agent_platforms[paw]}'
                                )
                                break

                    if not found and paw not in agent_platforms:
                        self.log.warning(
                            f'[BASTION DEBUG] FAILED to find platform for PAW {paw}'
                        )

                # OS Filter 적용 (agent_platforms 중 하나라도 매칭되면 포함)
                if os_filter:
                    platform_match = any(
                        os_filter in (platform or '').lower()
                        for platform in agent_platforms.values()
                    )
                    if not platform_match:
                        self.log.info(
                            f'[BASTION] Operation {op.name} 스킵: OS filter 미매칭 ({os_filter})'
                        )
                        continue

                # Search Filter 적용 (작전명, agent PAW, technique 검색)
                if search_query:
                    search_match = False
                    # 작전명 검색
                    if search_query in (op.name or '').lower():
                        search_match = True
                    # Agent PAW 검색
                    for paw in agent_paws:
                        if search_query in (paw or '').lower():
                            search_match = True
                            break
                    # Technique ID 검색
                    for tech_id in op_techniques:
                        if search_query in tech_id.lower():
                            search_match = True
                            break
                    if not search_match:
                        self.log.info(
                            f'[BASTION] Operation {op.name} 스킵: search 미매칭 ({search_query})'
                        )
                        continue

                # started/finished 처리 (datetime 또는 str)
                started = op.start.isoformat() if isinstance(op.start, datetime) else op.start
                finished = None
                if op.finish:
                    finished = op.finish.isoformat() if isinstance(op.finish, datetime) else op.finish

                operations_data.append({
                    'id': op.id,
                    'name': op.name,
                    'state': op.state,
                    'started': started,
                    'finished': finished,
                    'attack_steps': attack_steps,
                    'techniques': list(op_techniques),
                    'agent_count': len(op.agents),
                    'agent_paws': agent_paws,          # Agent PAW 목록 (OS filter용)
                    'agent_platforms': agent_platforms  # PAW -> Platform 매핑
                })
                filtered_ops.append(op)

            # 2. Wazuh Agent 정보 조회 (agent_id -> OS 매핑)
            wazuh_agent_os_map = {}
            timeout = aiohttp.ClientTimeout(total=30)

            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(ssl=self.verify_ssl)
            ) as session:
                # Wazuh Manager API에서 JWT 토큰 획득
                auth = aiohttp.BasicAuth(self.username, self.password)
                async with session.post(
                    f'{self.manager_url}/security/user/authenticate?raw=true',
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        token = await resp.text()
                        headers = {'Authorization': f'Bearer {token}'}

                        # 모든 Wazuh agent 조회
                        async with session.get(
                            f'{self.manager_url}/agents',
                            headers=headers,
                            params={'limit': 500}
                        ) as agents_resp:
                            if agents_resp.status == 200:
                                agents_data = await agents_resp.json()
                                for agent in agents_data.get('data', {}).get('affected_items', []):
                                    agent_id = agent.get('id')
                                    agent_os = agent.get('os', {}).get('platform', '').lower()
                                    if agent_id and agent_os:
                                        wazuh_agent_os_map[agent_id] = agent_os

            # 3. Wazuh 탐지 이벤트 조회
            # 오퍼레이션 필터가 있을 때는 해당 작전의 실행 시간 범위로 쿼리
            time_range_query = {}

            if operation_id_filter and filtered_ops:
                # 필터링된 오퍼레이션의 시작~종료 시간 범위 계산
                op_start_times = []
                op_end_times = []

                for op in filtered_ops:
                    if op.start:
                        # op.start가 문자열일 수 있으므로 datetime으로 변환
                        if isinstance(op.start, str):
                            try:
                                op_start = datetime.fromisoformat(op.start.replace('Z', '+00:00')).replace(tzinfo=None)
                            except Exception:
                                op_start = None
                        else:
                            op_start = op.start.replace(tzinfo=None) if op.start.tzinfo else op.start
                        if op_start:
                            op_start_times.append(op_start)

                    if op.finish:
                        # op.finish가 문자열일 수 있으므로 datetime으로 변환
                        if isinstance(op.finish, str):
                            try:
                                op_end = datetime.fromisoformat(op.finish.replace('Z', '+00:00')).replace(tzinfo=None)
                            except Exception:
                                op_end = None
                        else:
                            op_end = op.finish.replace(tzinfo=None) if op.finish.tzinfo else op.finish
                        if op_end:
                            op_end_times.append(op_end)

                if op_start_times:
                    earliest_start = min(op_start_times)
                    # 작전 시작 30초 전부터 조회 (사전 탐지 포함)
                    query_start = (earliest_start - timedelta(seconds=30)).isoformat()

                    if op_end_times:
                        latest_end = max(op_end_times)
                    else:
                        # 종료 시간이 없으면 현재 시간 사용
                        latest_end = datetime.utcnow()

                    # 작전 종료 30초 후까지 조회 (지연 탐지 포함)
                    query_end = (latest_end + timedelta(seconds=30)).isoformat()

                    time_range_query = {
                        "range": {
                            "timestamp": {
                                "gte": query_start,
                                "lte": query_end
                            }
                        }
                    }

                    self.log.info(
                        f'[BASTION] Operation 시간 범위 쿼리: {query_start} ~ {query_end}'
                    )
                else:
                    # 시작 시간이 없으면 기본 범위 사용
                    time_range_query = {"range": {"timestamp": {"gte": f"now-{hours}h"}}}
            else:
                # 오퍼레이션 필터가 없으면 기본 시간 범위 사용
                time_range_query = {"range": {"timestamp": {"gte": f"now-{hours}h"}}}

            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": min_level}}},
                            time_range_query
                        ]
                    }
                },
                "size": 1000,
                "sort": [{"timestamp": {"order": "asc"}}],
                "_source": [
                    "@timestamp", "timestamp", "rule.id", "rule.level", "rule.description",
                    "data.mitre", "data.mitre.id", "data.mitre.tactic",
                    "agent.id", "agent.name", "agent.ip", "rule.mitre.technique", "rule.mitre.id",
                    "location", "full_log", "data.audit.command", "data.audit.exe",
                    "data.audit.type", "data.audit.cwd", "data.srcip", "data.dstip"
                ]
            }

            detected_techniques = set()
            detection_events = []

            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(ssl=self.verify_ssl)
            ) as session:
                auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                async with session.post(
                    f'{self.indexer_url}/wazuh-alerts-*/_search',
                    json=query,
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        alerts = data.get('hits', {}).get('hits', [])

                        for alert in alerts:
                            source = alert.get('_source', {})
                            doc_id = alert.get('_id')
                            ts = source.get('@timestamp') or source.get('timestamp')

                            # MITRE 기법 추출
                            mitre_data = source.get('data', {}).get('mitre', {})
                            rule_mitre = source.get('rule', {}).get('mitre', {})
                            technique_id = None
                            tactic = None

                            # 1. data.mitre.id 확인
                            if isinstance(mitre_data, dict):
                                technique_id = mitre_data.get('id')
                                tactic = mitre_data.get('tactic', [])
                                if isinstance(tactic, list) and tactic:
                                    tactic = tactic[0]

                            # 2. rule.mitre.id 확인 (배열인 경우 첫 번째 요소 추출)
                            if not technique_id and isinstance(rule_mitre, dict):
                                rule_mitre_id = rule_mitre.get('id')
                                if isinstance(rule_mitre_id, list) and rule_mitre_id:
                                    technique_id = rule_mitre_id[0]
                                elif isinstance(rule_mitre_id, str):
                                    technique_id = rule_mitre_id

                                # tactic도 추출
                                if not tactic:
                                    rule_mitre_tactic = rule_mitre.get('tactic')
                                    if isinstance(rule_mitre_tactic, list) and rule_mitre_tactic:
                                        tactic = rule_mitre_tactic[0]
                                    elif isinstance(rule_mitre_tactic, str):
                                        tactic = rule_mitre_tactic

                            # 3. 규칙 ID 매핑 테이블 사용
                            if not technique_id:
                                rule_id = str(source.get('rule', {}).get('id', ''))
                                technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                            # ⚠️ detected_techniques는 IntegrationEngine 매칭 후에만 추가
                            # if technique_id:
                            #     detected_techniques.add(technique_id)

                            agent_id = source.get('agent', {}).get('id')
                            agent_os = wazuh_agent_os_map.get(agent_id, 'unknown')

                            # 상세 정보 필드 추출
                            data_obj = source.get('data', {})
                            audit_obj = data_obj.get('audit', {}) if isinstance(data_obj, dict) else {}

                            detection_events.append({
                                'doc_id': doc_id,
                                'timestamp': ts,
                                'rule_id': source.get('rule', {}).get('id'),
                                'rule_level': source.get('rule', {}).get('level'),
                                'description': source.get('rule', {}).get('description'),
                                'agent_name': source.get('agent', {}).get('name'),
                                'agent_id': agent_id,
                                'agent_ip': source.get('agent', {}).get('ip'),
                                'agent_os': agent_os,
                                'technique_id': technique_id,
                                'tactic': tactic,
                                'match_status': 'unmatched',
                                'attack_step_id': None,
                                'match_source': 'wazuh',
                                'opId': None,
                                # 상세 정보 필드
                                'location': source.get('location'),
                                'full_log': source.get('full_log'),
                                'audit_command': audit_obj.get('command'),
                                'audit_exe': audit_obj.get('exe'),
                                'audit_type': audit_obj.get('type'),
                                'audit_cwd': audit_obj.get('cwd'),
                                'srcip': data_obj.get('srcip') if isinstance(data_obj, dict) else None,
                                'dstip': data_obj.get('dstip') if isinstance(data_obj, dict) else None,
                            })

            # 3-A. IntegrationEngine 기반으로 detection_events 매칭 정보 반영
            self.log.info(
                f"[BASTION DEBUG] 매칭 조건 확인: "
                f"has_integration_engine={hasattr(self, 'integration_engine')}, "
                f"integration_engine_exists={self.integration_engine is not None if hasattr(self, 'integration_engine') else False}, "
                f"filtered_ops_count={len(filtered_ops)}"
            )

            try:
                if hasattr(self, "integration_engine") and self.integration_engine and filtered_ops:
                    # 1) detection_events 인덱스 구축: (rule_id, agent_id) -> [(event_dt, ev), ...]
                    index_by_rule_agent: Dict[tuple, List[tuple]] = {}

                    self.log.info(
                        f"[BASTION DEBUG] 매칭 시작 - detection_events: {len(detection_events)}개"
                    )

                    # 🔍 디버그: detection_events 샘플 출력
                    if detection_events:
                        sample = detection_events[0]
                        self.log.info(
                            f"[BASTION DEBUG] Sample detection event: "
                            f"rule_id={sample.get('rule_id')}, "
                            f"technique_id={sample.get('technique_id')}, "
                            f"timestamp={sample.get('timestamp')}, "
                            f"agent_id={sample.get('agent_id')}"
                        )

                    # 인덱스 구축 (안전한 처리)
                    for ev in detection_events:
                        try:
                            ts = ev.get("timestamp")
                            rule_id = ev.get("rule_id")
                            agent_id = ev.get("agent_id") or ""

                            if not ts or not rule_id:
                                continue

                            # timestamp 파싱 (안전한 처리)
                            try:
                                ev_dt = date_parser.parse(ts)
                            except Exception as e:
                                self.log.debug(f'[BASTION] timestamp 파싱 실패: {ts}, error: {e}')
                                continue

                            # 문자열로 변환해서 키로 사용 (int도 str로 통일, 공백 제거)
                            rule_key = str(rule_id).strip()
                            agent_key = str(agent_id).strip() if agent_id else ""
                            key = (rule_key, agent_key)

                            index_by_rule_agent.setdefault(key, []).append((ev_dt, ev))
                        except Exception as idx_err:
                            self.log.debug(f"[BASTION] 인덱스 구축 중 에러 (skip): {idx_err}")
                            continue

                    # 정렬해두면 나중에 시간 차 계산할 때 조금 낫다
                    for key in index_by_rule_agent:
                        try:
                            index_by_rule_agent[key].sort(key=lambda x: x[0])
                        except Exception:
                            pass

                    self.log.info(
                        f"[BASTION DEBUG] 인덱스 구축 완료: {len(index_by_rule_agent)}개 키"
                    )

                    # ±5분 이내면 같은 이벤트로 본다 (로그 전송 지연 고려)
                    # 네트워크 지연, Wazuh 처리 시간, Elasticsearch 인덱싱 시간 등을 고려
                    # 실제 테스트 결과 3-4분 지연이 발생하므로 여유있게 설정
                    THRESHOLD_SEC = 300
                    total_matched = 0

                    self.log.info(
                        f"[BASTION] dashboard correlation 시작: "
                        f"ops={len(filtered_ops)}, detections={len(detection_events)}"
                    )

                    for op in filtered_ops:
                        try:
                            self.log.info(
                                f"[BASTION DEBUG] IntegrationEngine.correlate() 호출: "
                                f"op={getattr(op, 'name', '')} ({getattr(op, 'id', '')})"
                            )
                            link_results = await self.integration_engine.correlate(op)

                            if not link_results:
                                self.log.info(f"[BASTION DEBUG] No link results for operation")
                                continue

                            self.log.info(
                                f"[BASTION DEBUG] IntegrationEngine 결과: {len(link_results)}개 링크"
                            )

                            # 🔍 각 링크의 매칭 결과 출력
                            for lr in link_results:
                                self.log.info(
                                    f"[BASTION DEBUG] Link: {lr.get('ability_name')} "
                                    f"(technique={lr.get('technique_id')}), "
                                    f"detected={lr.get('detected')}, "
                                    f"matches={lr.get('match_count')}"
                                )

                        except Exception as ce:
                            self.log.warning(
                                f"[BASTION] correlate 실패 (op={getattr(op, 'id', '')}): {ce}"
                            )
                            import traceback
                            traceback.print_exc()
                            continue

                        op_name = getattr(op, "name", "")
                        op_id = getattr(op, "id", "")
                        op_label = f"{op_name} ({op_id})" if (op_name or op_id) else op_id

                        for lr in link_results or []:
                            try:
                                link_id = lr.get("link_id")
                                matches_list = lr.get("matches", [])

                                # ✅ detected=True인 링크의 technique_id를 detected_techniques에 추가
                                if lr.get("detected", False):
                                    tech_id = lr.get("technique_id")
                                    if tech_id:
                                        detected_techniques.add(tech_id)

                                # 🔍 매칭 시작 디버그 (조건 없이 항상 출력)
                                if matches_list:
                                    self.log.info(
                                        f"[BASTION DEBUG] Processing {len(matches_list)} matches for link {link_id}"
                                    )

                                for idx, m in enumerate(matches_list):
                                    try:
                                        # 🔍 첫 번째 매칭 디버그 (조건 없이 항상 출력)
                                        if idx == 0:
                                            self.log.info(
                                                f"[BASTION DEBUG] First match data: "
                                                f"keys={list(m.keys())}, "
                                                f"agent={m.get('agent')}, "
                                                f"agent.id={m.get('agent.id')}"
                                            )

                                        ts = m.get("@timestamp") or m.get("timestamp")
                                        if not ts:
                                            continue

                                        # timestamp 파싱
                                        try:
                                            m_dt = date_parser.parse(ts)
                                        except Exception:
                                            continue

                                        # rule_id 추출 (안전한 처리, 타입 통일)
                                        rule_id = m.get("rule.id") or m.get("rule_id")
                                        if not rule_id:
                                            continue

                                        # rule_id를 문자열로 통일 (int도 str로 변환)
                                        rule_key = str(rule_id).strip()

                                        # agent_id 추출 (dict/flat 모두 대응)
                                        agent = m.get("agent")
                                        if isinstance(agent, dict) and agent:
                                            agent_id = agent.get("id")
                                        else:
                                            agent_id = m.get("agent.id") or m.get("agent_id")

                                        # agent_id도 문자열로 통일
                                        agent_key = str(agent_id).strip() if agent_id else ""

                                        # 매칭 시도 (여러 키 조합 - 우선순위 순서)
                                        keys_to_try = []
                                        if agent_key:
                                            # 1순위: rule_id + agent_id 둘 다 일치
                                            keys_to_try.append((rule_key, agent_key))
                                        # 2순위: rule_id만 일치 (agent_id 무시)
                                        keys_to_try.append((rule_key, ""))

                                        matched_here = False
                                        match_details = None

                                        for key in keys_to_try:
                                            candidates = index_by_rule_agent.get(key, [])
                                            if not candidates:
                                                continue

                                            # 가장 가까운 이벤트 하나 찾기
                                            best_ev = None
                                            best_diff = None

                                            for ev_dt, ev in candidates:
                                                try:
                                                    diff = abs((ev_dt - m_dt).total_seconds())
                                                    if best_diff is None or diff < best_diff:
                                                        best_diff = diff
                                                        best_ev = ev
                                                except Exception:
                                                    continue

                                            if best_ev is not None and best_diff is not None and best_diff <= THRESHOLD_SEC:
                                                # 매칭 성공
                                                best_ev["match_status"] = "matched"
                                                best_ev["attack_step_id"] = link_id
                                                best_ev["match_source"] = "wazuh"
                                                best_ev["opId"] = op_label
                                                best_ev["ability_name"] = lr.get("ability_name", "")
                                                best_ev["ability_id"] = lr.get("ability_id", "")
                                                total_matched += 1
                                                matched_here = True
                                                match_details = f"diff={best_diff:.1f}s, key={key}"

                                                self.log.info(
                                                    f"[BASTION DEBUG] ✓ 매칭 성공: "
                                                    f"rule_id={rule_key}, agent_id={agent_key}, "
                                                    f"time_diff={best_diff:.1f}s, link={link_id}"
                                                )
                                                break  # 이 match(m)는 더 이상 다른 key로 안 봐도 됨
                                            elif best_ev is not None and best_diff is not None:
                                                # 후보는 있지만 시간 차이 초과
                                                self.log.warning(
                                                    f"[BASTION] ✗ 시간 초과: "
                                                    f"rule_id={rule_key}, agent_id={agent_key}, "
                                                    f"time_diff={best_diff:.1f}s > {THRESHOLD_SEC}s, link={link_id}"
                                                )

                                        if not matched_here:
                                            # 매칭 실패 시 상세 정보 로깅
                                            self.log.warning(
                                                f"[BASTION] ✗ 매칭 실패: "
                                                f"rule_id={rule_key}, agent_id={agent_key}, "
                                                f"ts={ts}, link={link_id}, "
                                                f"candidates={sum(len(index_by_rule_agent.get(k, [])) for k in keys_to_try)}"
                                            )
                                    except Exception as match_err:
                                        self.log.debug(f"[BASTION] 개별 매칭 에러 (skip): {match_err}")
                                        continue
                            except Exception as link_err:
                                self.log.debug(f"[BASTION] 링크 처리 에러 (skip): {link_err}")
                                continue

                    self.log.info(
                        f"[BASTION] dashboard correlation matched events: {total_matched}"
                    )
            except Exception as e:
                self.log.warning(f"[BASTION] dashboard correlation 반영 실패: {e}")
                import traceback
                traceback.print_exc()

            # 🔻 매칭된 탐지 이벤트 카운트 (KPI용)
            matched_detection_events = [
                ev for ev in detection_events
                if ev.get('match_status') == 'matched'
            ]
            matched_detections_count = len(matched_detection_events)

            # 🔻 op 필터 있을 때: 해당 오퍼레이션에 MATCHED된 이벤트만 표시
            # 🔻 op 필터 없을 때(="all"): 모든 Wazuh 알림 표시 (matched + unmatched)
            before = len(detection_events)
            if operation_id_filter:
                # 특정 작전 선택 시: 매칭된 이벤트만 표시
                detection_events = matched_detection_events
                self.log.info(
                    f"[BASTION] op_filter={operation_id_filter}: MATCHED 이벤트만 표시 "
                    f"(전체 알림={before}, 매칭된 탐지={len(detection_events)})"
                )
            else:
                # all 필터 (오퍼레이션 선택 안함): 모든 Wazuh 알림 표시 (matched + unmatched)
                # match_status가 설정되지 않은 이벤트는 'unmatched'로 설정
                for ev in detection_events:
                    if not ev.get('match_status'):
                        ev['match_status'] = 'unmatched'
                self.log.info(
                    f"[BASTION] all 필터: 모든 Wazuh 알림 표시 "
                    f"(전체 알림={before}, 매칭된 탐지={len(matched_detection_events)})"
                )

            # 4. Security Posture Score 계산 (Cymulate/AttackIQ 스타일)
            agents = await self.data_svc.locate('agents')
            total_agents = len(agents)

            # Detection Rate 계산: 전체 공격 시도 대비 탐지된 공격 비율
            # operation_techniques는 set(고유 기법)이 아닌 전체 링크 개수
            total_attack_links = total_attack_steps  # 이미 계산된 전체 링크 개수

            # detected_links 계산: IntegrationEngine에서 detected=True인 링크 개수
            detected_links = 0
            if hasattr(self, 'integration_engine') and self.integration_engine and filtered_ops:
                for op in filtered_ops:
                    try:
                        link_results = await self.integration_engine.correlate(op)
                        for lr in link_results:
                            if lr.get('detected', False):
                                detected_links += 1
                    except Exception:
                        continue

            # Coverage 계산: 탐지된 링크 / 전체 링크
            coverage = (
                detected_links / total_attack_links
                if total_attack_links > 0 else 0.0
            )

            detection_rate = round(coverage * 100, 1)
            security_score = int(detection_rate)

            # 🔍 디버그 로그
            self.log.info(
                f"[BASTION DEBUG] Detection Rate 계산: "
                f"total_attack_links={total_attack_links}, "
                f"detected_links={detected_links}, "
                f"coverage={coverage}, "
                f"detection_rate={detection_rate}%"
            )

            if security_score >= 90:
                security_grade = 'A'
            elif security_score >= 80:
                security_grade = 'B'
            elif security_score >= 70:
                security_grade = 'C'
            elif security_score >= 60:
                security_grade = 'D'
            else:
                security_grade = 'F'

            # MTTD 계산 (Mean Time To Detection)
            mttd_seconds = 0
            mttd_count = 0
            for op in operations_data:
                if op.get('attack_steps'):
                    for step in op['attack_steps']:
                        step_time = step.get('timestamp')
                        if step_time:
                            step_technique = step.get('technique_id')
                            for event in detection_events:
                                if event.get('technique_id') == step_technique:
                                    try:
                                        attack_time = date_parser.parse(step_time).replace(tzinfo=None)
                                        detection_time = date_parser.parse(
                                            event['timestamp']
                                        ).replace(tzinfo=None)
                                        time_diff = (detection_time - attack_time).total_seconds()
                                        if time_diff >= 0:
                                            mttd_seconds += time_diff
                                            mttd_count += 1
                                    except Exception:
                                        pass

            mttd_minutes = round(mttd_seconds / 60 / mttd_count, 1) if mttd_count > 0 else 0

            # Critical Gaps (시뮬레이션했지만 탐지 안된 공격 횟수)
            critical_gaps = total_attack_links - detected_links

            # Tactic Coverage
            all_tactics = set()
            for op in operations_data:
                for step in op.get('attack_steps', []):
                    if step.get('tactic'):
                        all_tactics.add(step['tactic'])

            tactic_coverage = len(all_tactics)

            # 🔍 디버그 로그
            self.log.info(
                f"[BASTION DEBUG] Tactic Coverage 계산: "
                f"operations_data={len(operations_data)}, "
                f"all_tactics={all_tactics}, "
                f"tactic_coverage={tactic_coverage}"
            )

            # 🔍 API 응답 직전 detection_events 상태 로깅
            if detection_events:
                self.log.info(
                    f"[BASTION DEBUG] API 반환 직전 detection_events 샘플 (처음 3개):"
                )
                for i, ev in enumerate(detection_events[:3]):
                    self.log.info(
                        f"  [{i}] ts={ev.get('timestamp')}, "
                        f"rule={ev.get('rule_id')}, "
                        f"status={ev.get('match_status')}, "
                        f"step={ev.get('attack_step_id')}, "
                        f"op={ev.get('opId')}"
                    )

            result = {
                'success': True,
                'kpi': {
                    'total_operations': len(operations_data),
                    'total_agents': total_agents,
                    'total_attack_steps': total_attack_steps,
                    # 🔻 매칭된 탐지 수만 표시 (공격과 일치하는 탐지만)
                    'total_detections': matched_detections_count,
                    # 🔻 추가: 전체 Wazuh 알림 수 (참고용)
                    'total_alerts': before,
                    # 🔻 추가: 탐지된 링크 수 (IntegrationEngine 기반)
                    'detected_links': detected_links,
                    'coverage': round(coverage, 2),
                    'last_seen': detection_events[0]['timestamp'] if detection_events else None,
                    'security_score': security_score,
                    'security_grade': security_grade,
                    'detection_rate': detection_rate,
                    'mttd_minutes': mttd_minutes,
                    'critical_gaps': critical_gaps,
                    'tactic_coverage': tactic_coverage
                },
                'operations': operations_data,
                'detection_events': detection_events[:400],  # 매칭된 이벤트만 최근 400건
                'query_time': datetime.utcnow().isoformat()
            }

            self.log.info(
                f'[BASTION] 대시보드 요약 생성 완료 (작전: {len(operations_data)}, '
                f'탐지: {len(detection_events)}, Score: {security_score}/{security_grade})'
            )
            return web.json_response(result)

        except Exception as e:
            self.log.error(f'[BASTION] 대시보드 요약 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)


    async def get_technique_coverage(self, request: web.Request) -> web.Response:
        """
        MITRE ATT&CK Technique 커버리지 분석 (Heat Map용)

        - Caldera 작전 링크에서 시뮬레이션된 technique 통계 수집
        - Wazuh Indexer에서 alert 조회해서 탐지된 technique 카운트
        """
        try:
            hours = int(request.query.get('hours', 24))
            self.log.info(f'[BASTION] Technique 커버리지 분석: 최근 {hours}시간')

            now_utc = datetime.utcnow()
            cutoff_time = now_utc - timedelta(hours=hours)

            # 1. Caldera operations & links 기반으로 "시뮬레이션된" technique 집계
            technique_stats: Dict[str, Dict[str, Any]] = {}

            operations = await self.data_svc.locate('operations')
            for op in operations:
                if not op.start:
                    continue

                # timezone-aware → naive 로 통일해서 비교
                op_start = op.start
                if isinstance(op_start, datetime):
                    if op_start.tzinfo:
                        op_start = op_start.replace(tzinfo=None)
                else:
                    # 문자열인 경우는 그냥 통과 (필터 못 씀)
                    pass

                if isinstance(op_start, datetime) and op_start < cutoff_time:
                    continue

                if not hasattr(op, 'chain') or not op.chain:
                    continue

                for link in op.chain:
                    ability = getattr(link, 'ability', None)
                    if not ability or not ability.technique_id:
                        continue

                    tech_id = ability.technique_id
                    if tech_id not in technique_stats:
                        technique_stats[tech_id] = {
                            'id': tech_id,
                            'name': ability.technique_name or tech_id,
                            'tactic': ability.tactic or 'unknown',
                            'simulated': 0,
                            'detected': 0,
                        }
                    technique_stats[tech_id]['simulated'] += 1

            # 2. IntegrationEngine을 사용해서 매칭된 탐지만 집계
            if technique_stats and hasattr(self, 'integration_engine') and self.integration_engine:
                try:
                    # 시간 범위 내의 operation들에 대해 correlation 실행
                    for op in operations:
                        if not op.start:
                            continue

                        op_start = op.start
                        if isinstance(op_start, datetime):
                            if op_start.tzinfo:
                                op_start = op_start.replace(tzinfo=None)

                        if isinstance(op_start, datetime) and op_start < cutoff_time:
                            continue

                        # IntegrationEngine으로 매칭 수행
                        try:
                            link_results = await self.integration_engine.correlate(op)

                            # 매칭된 이벤트에서 technique ID 추출
                            for link_result in link_results:
                                if link_result.get('detected', False):
                                    # technique_id 추출
                                    tech_id = link_result.get('technique_id')

                                    if tech_id and tech_id in technique_stats:
                                        # 탐지된 공격 1건으로 카운트 (여러 alert가 매칭되어도 1건)
                                        technique_stats[tech_id]["detected"] += 1
                        except Exception as corr_err:
                            self.log.debug(f"[BASTION] Operation {op.id} correlation 실패: {corr_err}")
                            continue

                except Exception as e:
                    self.log.warning(f"[BASTION] IntegrationEngine을 이용한 탐지 집계 실패: {e}")

            # 3. Detection rate / status 계산
            techniques: List[Dict[str, Any]] = []
            for tech_id, stats in technique_stats.items():
                simulated = stats["simulated"]
                detected = stats["detected"]
                rate = (detected / simulated * 100.0) if simulated > 0 else 0.0

                if simulated == 0:
                    status = "not_simulated"  # 회색
                elif detected == 0:
                    status = "gap"            # 빨강
                elif rate < 80:
                    status = "partial"        # 노랑
                else:
                    status = "complete"       # 초록

                techniques.append({
                    "id": tech_id,
                    "name": stats["name"],
                    "tactic": stats["tactic"],
                    "simulated": simulated,
                    "detected": detected,
                    "detection_rate": round(rate, 1),
                    "status": status,
                })

            # 4. Tactic별 집계
            tactics: Dict[str, Dict[str, Any]] = {}
            for tech in techniques:
                tactic = tech["tactic"]
                if tactic not in tactics:
                    tactics[tactic] = {
                        "name": tactic,
                        "techniques": [],
                        "total_simulated": 0,
                        "total_detected": 0,
                    }
                tactics[tactic]["techniques"].append(tech)
                tactics[tactic]["total_simulated"] += tech["simulated"]
                tactics[tactic]["total_detected"] += tech["detected"]

            for t in tactics.values():
                total = t["total_simulated"]
                detected = t["total_detected"]
                t["coverage"] = round((detected / total * 100.0) if total > 0 else 0.0, 1)

            summary = {
                "total_techniques": len(techniques),
                "total_simulated": sum(t["simulated"] for t in techniques),
                "total_detected": sum(t["detected"] for t in techniques),
                "overall_detection_rate": round(
                    (
                        sum(t["detected"] for t in techniques)
                        / sum(t["simulated"] for t in techniques)
                        * 100.0
                    )
                    if techniques and sum(t["simulated"] for t in techniques) > 0
                    else 0.0,
                    1,
                ),
            }

            return web.json_response({
                "techniques": techniques,
                "tactics": list(tactics.values()),
                "summary": summary,
                "time_range": {
                    "hours": hours,
                    "from": cutoff_time.isoformat(),
                    "to": now_utc.isoformat(),
                },
            })

        except Exception as e:
            self.log.error(f"[BASTION] Technique 커버리지 조회 실패: {e}", exc_info=True)
            return web.json_response({
                "error": str(e),
                "techniques": [],
                "tactics": [],
                "summary": {
                    "total_techniques": 0,
                    "total_simulated": 0,
                    "total_detected": 0,
                    "overall_detection_rate": 0.0,
                },
            }, status=500)


    async def continuous_monitoring(self):
        """지속적인 Wazuh 알림 모니터링 (백그라운드 태스크)"""
        self.log.info(f'[BASTION] 지속 모니터링 시작 (간격: {self.monitor_interval}초)')

        while True:
            try:
                await asyncio.sleep(self.monitor_interval)

                # TODO: 알림 모니터링 및 자동 대응 로직
                self.log.debug('[BASTION] 모니터링 주기 실행')

            except asyncio.CancelledError:
                self.log.info('[BASTION] 지속 모니터링 중지됨')
                break
            except Exception as e:
                self.log.error(f'[BASTION] 모니터링 오류: {e}')
                await asyncio.sleep(60)
