"""
BASTION Service - Core logic for Caldera and Wazuh integration
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
    logging.getLogger('bastion').warning(f'[BASTION] IntegrationEngine local import failed, using fallback: {e}')
    from importlib import import_module
    IntegrationEngine = import_module('integration_engine').IntegrationEngine

class BASTIONService:
    """Caldera-Wazuh Integration Service"""

    # HTTP timeout constants (in seconds)
    TIMEOUT_HEALTH = 5      # Health check (fast response required)
    TIMEOUT_AUTH = 10       # Authentication and short API calls
    TIMEOUT_QUERY = 30      # Data queries and complex queries

    # Wazuh Rule ID → MITRE ATT&CK Technique mapping
    # Manual mapping since Wazuh default rules don't have MITRE tags
    RULE_MITRE_MAPPING = {
        # Authentication and Accounts
        '5715': 'T1078',      # SSH authentication success → Valid Accounts
        '5501': 'T1078',      # PAM: Login session opened → Valid Accounts
        '5402': 'T1078.003',  # Successful sudo to ROOT → Valid Accounts: Local Accounts

        # Network Detection
        '20101': 'T1046',  # IDS event
        '533': 'T1049',       # netstat ports changed → System Network Connections Discovery

        # System Detection
        '510': 'T1082',       # rootcheck anomaly → System Information Discovery
        '502': 'T1082',       # Wazuh server started → System Information Discovery
        '503': 'T1082',       # Wazuh agent started → System Information Discovery

        # SCA (Security Configuration Assessment)
        '19005': 'T1082',     # SCA summary → System Information Discovery
        '19007': 'T1082',     # SCA high severity → System Information Discovery
        '19008': 'T1082',     # SCA medium severity → System Information Discovery
        '19009': 'T1082',     # SCA low severity → System Information Discovery

        # File Access
        '550': 'T1083',       # Integrity checksum changed → File and Directory Discovery
        '554': 'T1083',       # File added to the system → File and Directory Discovery

        # Process
        '592': 'T1059',       # Process creation → Command and Scripting Interpreter
        '594': 'T1059',       # Process execution → Command and Scripting Interpreter
        
        # Reconnaissance
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
            services: Caldera services dictionary
            config: BASTION configuration
        """
        self.services = services
        self.data_svc = services.get('data_svc')
        self.rest_svc = services.get('rest_svc')
        self.app_svc = services.get('app_svc')
        self.knowledge_svc = services.get('knowledge_svc')
        self.log = self.app_svc.log if self.app_svc else logging.getLogger('bastion')

        # Wazuh configuration
        self.manager_url = config.get('wazuh_manager_url', 'https://localhost:55000')
        self.indexer_url = config.get('wazuh_indexer_url', 'https://localhost:9200')
        self.username = config.get('wazuh_username', 'wazuh')
        self.password = config.get('wazuh_password', 'wazuh')
        self.indexer_username = config.get('indexer_username', 'admin')
        self.indexer_password = config.get('indexer_password', 'SecretPassword')
        # Elasticsearch (for Discover) - Do not reuse Wazuh Manager
        self.elastic_url = config.get('elastic_url', 'http://elasticsearch:9200')
        self.elastic_username = config.get('elastic_username', 'elastic')
        self.elastic_password = config.get('elastic_password', 'changeme')
        self.verify_ssl = config.get('verify_ssl', False)
        self.monitor_interval = config.get('alert_query_interval', 300)
        # IntegrationEngine initialization
        try:
            self.log.info("[BASTION] IntegrationEngine initialization started...")
            overrides = config.get("integration_engine") or {}
            self.log.info(f"[BASTION] IntegrationEngine overrides: {overrides}")
            # Pass RULE_MITRE_MAPPING to IntegrationEngine
            self.integration_engine = IntegrationEngine(overrides, rule_mitre_mapping=self.RULE_MITRE_MAPPING)
            self.log.info("[BASTION] IntegrationEngine initialization complete ✓")
            self.log.info(f"[BASTION] IntegrationEngine client type: {type(self.integration_engine.client).__name__}")
            self.log.info(f"[BASTION] Rule-MITRE mapping: {len(self.RULE_MITRE_MAPPING)} rules")
        except Exception as e:
            self.integration_engine = None
            self.log.error(f"[BASTION] IntegrationEngine initialization failed: {e}")
            import traceback
            traceback.print_exc()

        # State management
        self.token = None
        self.token_expiry = None
        self.last_alert_time = datetime.utcnow()
        self.is_authenticated = False

        

    async def authenticate(self):
        """Wazuh Manager API authentication"""
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
                        self.log.info('[BASTION] Wazuh API authentication successful')
                        return True
                    else:
                        error_text = await resp.text()
                        raise Exception(f'Authentication failed (HTTP {resp.status}): {error_text}')

        except aiohttp.ClientConnectorError as e:
            self.log.error(f'[BASTION] Wazuh Manager connection failed: {e}')
            self.log.error(f'[BASTION] Please verify {self.manager_url} address is correct')
            raise
        except asyncio.TimeoutError:
            self.log.error('[BASTION] Wazuh API connection timeout (10 seconds)')
            raise
        except Exception as e:
            self.log.error(f'[BASTION] Wazuh authentication error: {e}')
            raise

    # -----------------------------
    # Elasticsearch (for Discover)
    # -----------------------------
    async def get_es_indices(self, request: web.Request) -> web.Response:
        """
        Return Elasticsearch index list (for Discover)
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
                        raise Exception(f'ES indices call failed (HTTP {resp.status}): {text}')
                    data = await resp.json()
                    indices = [item.get('index') for item in data if item.get('index')]
                    # Remove duplicates + sort
                    unique = sorted(set(indices))
                    return web.json_response(unique)
        except Exception as e:
            self.log.error(f'[BASTION] ES index query failed: {e}')
            return web.json_response({'error': str(e)}, status=500)

    async def search_es(self, request: web.Request) -> web.Response:
        """
        Elasticsearch search proxy (for Discover)
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
                        raise Exception(f'ES search failed (HTTP {resp.status}): {text}')
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
            self.log.error(f'[BASTION] ES search failed: {e}')
            return web.json_response({'error': str(e)}, status=500)

    def _build_es_query(self, kql: str, time_range: Dict[str, str], filters: List[Dict[str, str]]):
        """
        Wrap Kibana KQL as simple query_string and add field filters/time range to bool.must
        """
        must_clauses = []
        must_not_clauses = []

        # KQL -> query_string (simple delegation)
        if kql:
            must_clauses.append({
                'query_string': {
                    'query': kql
                }
            })

        # Time range (based on @timestamp)
        time_from = (time_range or {}).get('from')
        time_to = (time_range or {}).get('to')
        if time_from or time_to:
            range_query = {'range': {'@timestamp': {}}}
            if time_from:
                range_query['range']['@timestamp']['gte'] = time_from
            if time_to:
                range_query['range']['@timestamp']['lte'] = time_to
            must_clauses.append(range_query)

        # Field filters
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
                        return web.json_response({'error': 'Elasticsearch authentication failed'}, status=401)
                    if resp.status != 200:
                        raise Exception(f'ES indices call failed (HTTP {resp.status}): {text}')
                    try:
                        data = json.loads(text)
                    except Exception:
                        data = []
                    indices = [item.get('index') for item in data if item.get('index')]
                    return web.json_response(indices)
        except (asyncio.TimeoutError, aiohttp.ClientError) as e:
            self.log.error(f'[Discover] Index query timeout/client error: {e}')
            return web.json_response({'error': 'Elasticsearch request failed'}, status=504)
        except Exception as e:
            self.log.error(f'[Discover] Index query failed: {e}')
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
                        return web.json_response({'error': 'Elasticsearch authentication failed'}, status=401)
                    if resp.status != 200:
                        raise Exception(f'ES search failed (HTTP {resp.status}): {text}')
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
            self.log.error(f'[Discover] Search timeout/client error: {e}')
            return web.json_response({'error': 'Elasticsearch request failed'}, status=504)
        except Exception as e:
            self.log.error(f'[Discover] Search failed: {e}')
            return web.json_response({'error': str(e)}, status=500)

    async def _ensure_authenticated(self):
        """Check token validity and re-authenticate"""
        if not self.token or not self.token_expiry:
            await self.authenticate()
        elif datetime.utcnow() >= self.token_expiry:
            self.log.info('[BASTION] Token expired, re-authenticating...')
            await self.authenticate()

    async def get_recent_alerts(self, request: web.Request) -> web.Response:
        """
        Get recent Wazuh alerts

        Query Parameters:
            hours: Query time range (default: 1 hour)
            min_level: Minimum severity level (default: 7)
        """
        try:
            hours = int(request.query.get('hours', 1))
            min_level = int(request.query.get('min_level', 7))

            self.log.info(f'[BASTION] Alert query request: last {hours} hours, level >= {min_level}')

            # OpenSearch query
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
                # Wazuh Indexer authentication
                auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                async with session.post(
                    f'{self.indexer_url}/wazuh-alerts-*/_search',
                    json=query,
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        alerts = data.get('hits', {}).get('hits', [])

                        # Extract MITRE techniques and add technique_id to each alert
                        techniques = set()
                        processed_alerts = []

                        for alert in alerts:
                            source = alert.get('_source', {})
                            

                            # 1. First check MITRE data directly from alert
                            # Extract technique ID from rule.mitre.id field
                            rule_data = source.get('rule', {})
                            mitre_data = rule_data.get('mitre', {})
                            technique_id = None

                            if isinstance(mitre_data, dict) and 'id' in mitre_data:
                                # mitre.id can be an array, so use the first value
                                mitre_ids = mitre_data['id']
                                if isinstance(mitre_ids, list) and len(mitre_ids) > 0:
                                    technique_id = mitre_ids[0]
                                elif isinstance(mitre_ids, str):
                                    technique_id = mitre_ids

                            # 2. Use rule ID mapping table if MITRE data is not available
                            if not technique_id:
                                rule_id = str(rule_data.get('id', ''))
                                technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                            if technique_id:
                                techniques.add(technique_id)

                            # Add mapped technique_id to each alert (for frontend display)
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

                        self.log.info(f'[BASTION] Alert query completed: {len(alerts)} alerts')
                        return web.json_response(result)
                    else:
                        error_text = await resp.text()
                        self.log.error(f'[BASTION] Indexer query failed: {error_text}')
                        return web.json_response({
                            'success': False,
                            'error': f'Indexer query failed: HTTP {resp.status}'
                        }, status=500)

        except Exception as e:
            self.log.error(f'[BASTION] Alert query failed: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def correlate_operation(self, request: web.Request) -> web.Response:
        """
        Correlation analysis between Caldera operation and Wazuh alerts
        (IntegrationEngine-based operation ↔ detection matching)
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

            # 1) Query Caldera operation
            operations = await self.data_svc.locate('operations', match={'id': operation_id})
            if not operations:
                return web.json_response({
                    'success': False,
                    'error': f'Operation {operation_id} not found'
                }, status=404)

            operation = operations[0]

            # 2) Calculate operation execution time range (safe timezone handling)
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
                self.log.debug(f'[BASTION] duration calculation failed: {e}')
                duration_seconds = 0

            # 3) Build MITRE technique & ability list from operation (safe processing)
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
                    self.log.debug(f'[BASTION] Error processing link (skip): {link_err}')
                    continue

            self.log.info(f'[BASTION] Operation executed techniques: {operation_techniques}')

            # 4) 🔹 Link-by-link detection matching using IntegrationEngine
            #    Uses index, time_window_sec, field mappings configured in conf/default.yml
            link_results = []
            try:
                link_results = await self.integration_engine.correlate(operation)
            except Exception as corr_err:
                self.log.error(f'[BASTION] IntegrationEngine correlate failed: {corr_err}')
                return web.json_response({
                    'success': False,
                    'error': f'Correlation failed: {str(corr_err)}'
                }, status=500)
            # link_results element example:
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

            # 5) Calculate detected techniques / matched alert list (safe processing)
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
                                # Format field names for Vue table
                                'timestamp': m.get('@timestamp') or m.get('timestamp'),
                                'rule_id': m.get('rule.id') or m.get('rule_id'),
                                'rule_level': m.get('level') or m.get('rule_level'),
                                'description': m.get('description', ''),
                                'agent_name': m.get('agent.name') or m.get('agent_name'),
                                'agent_id': m.get('agent.id') or m.get('agent_id'),
                                'technique_id': tech or m.get('mitre.id') or m.get('technique_id'),
                                # Include which link/ability the detection came from
                                'link_id': link_id,
                                'ability_name': ability_name,
                                'match_status': 'MATCHED',
                                'match_source': 'wazuh'
                            })
                        except Exception as alert_err:
                            self.log.debug(f'[BASTION] Error processing alert (skip): {alert_err}')
                            continue
                except Exception as lr_err:
                    self.log.debug(f'[BASTION] Error processing link_result (skip): {lr_err}')
                    continue

            # 6) Calculate matching and detection rate (maintain existing structure)
            matched_techniques = operation_techniques.intersection(detected_techniques)
            undetected_techniques = operation_techniques - detected_techniques

            detection_rate = 0.0
            if operation_techniques:
                detection_rate = len(matched_techniques) / len(operation_techniques)

            # 7) Generate final correlation result (maintain existing response schema + add links)
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
                # 🔹 Include link-by-link raw results for more detailed frontend usage
                'links': link_results,
                # 🔹 Keep existing alerts_matched (for Vue Detection Table)
                'alerts_matched': alerts_matched,
                'total_alerts': len(alerts_matched)
            }

            self.log.info(
                f'[BASTION] Correlation analysis complete (IntegrationEngine): '
                f'detection rate {detection_rate:.1%}, links={len(link_results)}, alerts={len(alerts_matched)}'
            )

            return web.json_response(correlation_result)

        except Exception as e:
            self.log.error(f'[BASTION] Correlation analysis failed: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)


    async def generate_detection_report(self, request: web.Request) -> web.Response:
        """Generate detection coverage report"""
        try:
            # TODO: Implementation needed
            report = {
                'success': True,
                'message': 'Detection report generation not implemented yet',
                'total_operations': 0,
                'detection_rate': 0.0
            }

            return web.json_response(report)

        except Exception as e:
            self.log.error(f'[BASTION] Report generation failed: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def create_adaptive_operation(self, request: web.Request) -> web.Response:
        """Create adaptive operation based on Wazuh data"""
        try:
            # TODO: Implementation needed
            return web.json_response({
                'success': True,
                'message': 'Adaptive operation not implemented yet'
            })

        except Exception as e:
            self.log.error(f'[BASTION] Adaptive operation creation failed: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def get_agents_with_detections(self, request: web.Request) -> web.Response:
        """
        Caldera Agents list + Wazuh Agent matching + Recent detection info

        Query Parameters:
            hours: Query time range (default: 1 hour)
            operation_id: Specific operation ID filter (optional)
            os_filter: OS platform filter (optional: Windows, Linux, macOS)
            search: Search query (optional)
        """
        try:
            hours = int(request.query.get('hours', 24))
            operation_id_filter = request.query.get('operation_id', '').strip()
            raw_os = request.query.get('os_filter') or request.query.get('os')
            os_filter = (raw_os or '').strip().lower()
            search_query = request.query.get('search', '').strip().lower()

            self.log.info(f'[BASTION] Agents query request (last {hours} hours detection, op_filter={operation_id_filter}, os={os_filter}, search={search_query})')

            # 1. Query Wazuh Agents (indexed by ID)
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
                            self.log.info(f'[BASTION] {len(wazuh_agents_by_id)} agents queried')
            except Exception as e:
                self.log.warning(f'[BASTION] Agents query failed: {e}')

            # 2. Query Caldera Agents
            agents = await self.data_svc.locate('agents')

            agents_data = []
            for agent in agents:
                # Determine agent alive status (timezone safe)
                alive = False
                if agent.last_seen:
                    try:
                        # Handle timezone-aware datetime
                        last_seen = agent.last_seen.replace(tzinfo=None) if agent.last_seen.tzinfo else agent.last_seen
                        alive = (datetime.utcnow() - last_seen).total_seconds() < 300  # Within 5 minutes
                    except Exception as e:
                        self.log.debug(f'[BASTION] Agent {agent.paw} alive status calculation failed: {e}')
                        alive = False

                # Handle last_seen (datetime or str)
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
                    'attack_steps_count': 0,  # Week 11: Attack steps count per agent
                    'detections_count': 0     # Week 11: Detections count per agent
                }

                # Wazuh Agent matching
                wazuh_agent = None
                wazuh_agent_id = None

                # 1) Priority: Find wazuh.agent.id from Agent links facts
                try:
                    if hasattr(agent, 'links') and agent.links:
                        for link in agent.links:
                            if hasattr(link, 'facts') and link.facts:
                                for fact in link.facts:
                                    if fact.trait == 'wazuh.agent.id':
                                        wazuh_agent_id = str(fact.value).strip()
                                        self.log.info(
                                            f'[BASTION] Agent {agent.paw}: '
                                            f'Wazuh ID {wazuh_agent_id} (found in links)'
                                        )
                                        break
                            if wazuh_agent_id:
                                break
                except Exception as e:
                    self.log.error(f'[BASTION] Error getting facts for agent {agent.paw}: {e}')

                # 2) Fallback: Map if Caldera agent.host == Wazuh agent.name
                if not wazuh_agent_id and agent.host:
                    host_key = (agent.host or '').lower()
                    fallback = wazuh_agents_by_name.get(host_key)
                    if fallback:
                        wazuh_agent_id = fallback.get('id')
                        self.log.info(
                            f'[BASTION DEBUG] Agent {agent.paw}: '
                            f'Wazuh mapping based on host="{agent.host}" → '
                            f'{wazuh_agent_id} ({fallback.get("name")})'
                        )

                # 3) If both fail, only log warning
                if not wazuh_agent_id:
                    self.log.warning(
                        f'[BASTION DEBUG] Agent {agent.paw}: '
                        f'Wazuh mapping failed (both facts/host mismatch)'
                    )


                # Query Wazuh agent info
                if wazuh_agent_id:
                    wazuh_agent = wazuh_agents_by_id.get(wazuh_agent_id)
                    if not wazuh_agent:
                        self.log.warning(f'[BASTION] Agent {agent.paw}: Wazuh ID {wazuh_agent_id} does not exist')

                agent_info['wazuh_matched'] = wazuh_agent is not None
                agent_info['wazuh_agent'] = wazuh_agent if wazuh_agent else None

                # 2. Query recent Wazuh detections for each agent (matched only)
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

                                        # 1. First check MITRE data directly from alert
                                        mitre_data = source.get('data', {}).get('mitre', {})
                                        technique_id = mitre_data.get('id') if isinstance(mitre_data, dict) else None

                                        # 2. Use rule ID mapping table if MITRE data is not available
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
                        self.log.warning(f'[BASTION] Agent {agent.paw} detection query failed: {e}')
                        # Return agent info even on error

                # 1. Detections count - Only count detections matched by IntegrationEngine
                matched_detections_count = 0

                # Count matched detections for this agent using IntegrationEngine
                if hasattr(self, 'integration_engine') and self.integration_engine:
                    try:
                        # Perform correlation for recent operations
                        all_operations = await self.data_svc.locate('operations')
                        cutoff_time = datetime.utcnow() - timedelta(hours=hours)

                        for op in all_operations:
                            # Filter to specific operation if operation_id_filter is set
                            if operation_id_filter and op.id != operation_id_filter:
                                continue

                            # Time range check
                            if op.start:
                                op_start = op.start.replace(tzinfo=None) if op.start.tzinfo else op.start
                                if isinstance(op_start, datetime) and op_start < cutoff_time:
                                    continue

                            # Perform IntegrationEngine correlation
                            try:
                                link_results = await self.integration_engine.correlate(op)

                                # Count only links with detected=True for this agent
                                for link_result in link_results:
                                    link_paw = link_result.get('paw')
                                    detected = link_result.get('detected', False)

                                    if link_paw == agent.paw and detected:
                                        matched_detections_count += 1
                            except Exception as corr_err:
                                self.log.debug(f"[BASTION] Agent {agent.paw} correlation failed: {corr_err}")
                                continue
                    except Exception as e:
                        self.log.warning(f"[BASTION] Agent {agent.paw} matched detection count failed: {e}")

                agent_info['detections_count'] = matched_detections_count

                # 2. Attack steps count - Calculate directly from operations
                try:
                    attack_steps_count = 0
                    all_operations = await self.data_svc.locate('operations')
                    cutoff_time = datetime.utcnow() - timedelta(hours=hours)

                    for op in all_operations:
                        # Filter to specific operation if operation_id_filter exists
                        if operation_id_filter and op.id != operation_id_filter:
                            continue

                        # Time range check
                        if op.start:
                            op_start = op.start.replace(tzinfo=None) if op.start.tzinfo else op.start
                            if isinstance(op_start, datetime) and op_start < cutoff_time:
                                continue

                        # Count links for this agent
                        for link in op.chain:
                            if hasattr(link, 'paw') and link.paw == agent.paw and link.finish:
                                attack_steps_count += 1

                    agent_info['attack_steps_count'] = attack_steps_count
                except Exception as e:
                    self.log.warning(f'[BASTION] Agent {agent.paw} attack steps calculation failed: {e}')

                # Apply OS Filter
                if os_filter:
                    platform = (agent.platform or '').lower()
                    self.log.debug(
                        f'[BASTION DEBUG] OS filter check: agent={agent.paw}, '
                        f'platform="{platform}", os_filter="{os_filter}"'
                    )
                    if os_filter not in platform:
                        continue

                # Apply Search Filter
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

                # Apply Operation Filter (include only agents participating in the operation)
                if operation_id_filter:
                    all_operations = await self.data_svc.locate('operations')
                    operation_match = False
                    for op in all_operations:
                        if op.id == operation_id_filter:
                            # Check if current agent is among this operation's agents
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

            self.log.info(f'[BASTION] {len(agents_data)} agents query completed')
            return web.json_response(result)

        except Exception as e:
            self.log.error(f'[BASTION] Agents query failed: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def health_check(self, request: web.Request) -> web.Response:
        """Check plugin and Wazuh connection status"""
        try:
            health = {
                'plugin': 'healthy',
                'wazuh_manager': 'unknown',
                'wazuh_indexer': 'unknown',
                'authenticated': self.is_authenticated,
                'timestamp': datetime.utcnow().isoformat()
            }

            # Check Wazuh Manager status
            try:
                await self._ensure_authenticated()
                health['wazuh_manager'] = 'healthy'
            except Exception as e:
                health['wazuh_manager'] = f'unhealthy: {str(e)}'

            # Check Wazuh Indexer status
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
            self.log.error(f'[BASTION] Health check failed: {e}', exc_info=True)
            return web.json_response({
                'plugin': 'unhealthy',
                'error': str(e)
            }, status=500)

    async def get_dashboard_summary(self, request: web.Request) -> web.Response:
        """
        Dashboard integrated data query (KPI, Operations, Tactic Coverage, Timeline)

        Query Parameters:
            hours: Query time range (default: 24 hours)
            min_level: Minimum severity level (default: 5)
            operation_id: Specific operation ID filter (optional)
            os_filter: OS platform filter (optional: Windows, Linux, macOS)
            search: Search query (optional)
        """
        try:
            hours = int(request.query.get('hours', 24))
            min_level = int(request.query.get('min_level', 5))
            operation_id_filter = request.query.get('operation_id', '').strip()
            raw_os = request.query.get('os_filter') or request.query.get('os')
            os_filter = (raw_os or '').strip().lower()
            search_query = request.query.get('search', '').strip().lower()

            self.log.info(
                f'[BASTION] Dashboard summary query: last {hours} hours '
                f'(op_filter={operation_id_filter}, os_filter={os_filter}, search={search_query})'
            )

            # 1. Query Operations list (Caldera)
            all_operations = await self.data_svc.locate('operations')
            all_agents = await self.data_svc.locate('agents')  # Query all agents

            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            operations_data = []
            filtered_ops: List[Any] = []
            total_attack_steps = 0
            operation_techniques = set()  # Techniques executed in all operations

            self.log.debug(
                f'[BASTION DEBUG] Total operations: {len(all_operations)}, cutoff_time: {cutoff_time}'
            )

            for op in all_operations:
                # 1) Operation ID filter
                if operation_id_filter and op.id != operation_id_filter:
                    continue

                # 2) Time filter: Apply only when operation_id_filter is not set
                include_by_time = True
                op_start = None

                if not operation_id_filter and op.start:
                    op_start = op.start.replace(tzinfo=None) if op.start.tzinfo else op.start
                    if isinstance(op_start, datetime) and op_start < cutoff_time:
                        include_by_time = False

                if not include_by_time:
                    continue

                # 3) Extract operation execution steps
                attack_steps = []
                op_techniques = set()

                for link in op.chain:
                    ability = link.ability
                    # Convert link.finish to isoformat if datetime object, use as-is if string
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
                        'paw': link.paw  # Agent ID added (for OS filter)
                    })

                    if ability.technique_id:
                        op_techniques.add(ability.technique_id)
                        operation_techniques.add(ability.technique_id)

                total_attack_steps += len(attack_steps)

                # Agent PAWs and platforms mapping
                agent_paws = []
                agent_platforms = {}

                # Collect all PAWs from attack_steps first
                attack_step_paws = set(step['paw'] for step in attack_steps)
                self.log.warning(
                    f'[BASTION DEBUG] Operation {op.name}: attack_step_paws = {attack_step_paws}'
                )

                # Find platform for each PAW from all_agents or op.agents/chain
                for paw in attack_step_paws:
                    found = False

                    # 1. Find from all_agents
                    for agent in all_agents:
                        if agent.paw == paw:
                            agent_platforms[paw] = agent.platform
                            agent_paws.append(paw)
                            found = True
                            break

                    # 2. Find from op.agents (if not in all_agents)
                    if not found:
                        for agent in op.agents:
                            if agent.paw == paw:
                                agent_platforms[paw] = agent.platform
                                agent_paws.append(paw)
                                found = True
                                break

                    # 3. Infer platform from executor
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

                # Apply OS Filter (include if any agent_platform matches)
                if os_filter:
                    platform_match = any(
                        os_filter in (platform or '').lower()
                        for platform in agent_platforms.values()
                    )
                    if not platform_match:
                        self.log.info(
                            f'[BASTION] Operation {op.name} skipped: OS filter mismatch ({os_filter})'
                        )
                        continue

                # Apply Search Filter (operation name, agent PAW, technique search)
                if search_query:
                    search_match = False
                    # Operation name search
                    if search_query in (op.name or '').lower():
                        search_match = True
                    # Agent PAW search
                    for paw in agent_paws:
                        if search_query in (paw or '').lower():
                            search_match = True
                            break
                    # Technique ID search
                    for tech_id in op_techniques:
                        if search_query in tech_id.lower():
                            search_match = True
                            break
                    if not search_match:
                        self.log.info(
                            f'[BASTION] Operation {op.name} skipped: search mismatch ({search_query})'
                        )
                        continue

                # Handle started/finished (datetime or str)
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
                    'agent_paws': agent_paws,          # Agent PAW list (for OS filter)
                    'agent_platforms': agent_platforms  # PAW -> Platform mapping
                })
                filtered_ops.append(op)

            # 2. Query Wazuh Agent info (agent_id -> OS mapping)
            wazuh_agent_os_map = {}
            timeout = aiohttp.ClientTimeout(total=30)

            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(ssl=self.verify_ssl)
            ) as session:
                # Get JWT token from Wazuh Manager API
                auth = aiohttp.BasicAuth(self.username, self.password)
                async with session.post(
                    f'{self.manager_url}/security/user/authenticate?raw=true',
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        token = await resp.text()
                        headers = {'Authorization': f'Bearer {token}'}

                        # Query all Wazuh agents
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

            # 3. Query Wazuh detection events
            # When operation filter exists, query within operation's execution time range
            time_range_query = {}

            if operation_id_filter and filtered_ops:
                # Calculate start~end time range for filtered operations
                op_start_times = []
                op_end_times = []

                for op in filtered_ops:
                    if op.start:
                        # Convert to datetime since op.start can be a string
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
                        # Convert to datetime since op.finish can be a string
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
                    # Query from 30 seconds before operation start (including pre-detection)
                    query_start = (earliest_start - timedelta(seconds=30)).isoformat()

                    if op_end_times:
                        latest_end = max(op_end_times)
                    else:
                        # Use current time if no end time
                        latest_end = datetime.utcnow()

                    # Query until 30 seconds after operation end (including delayed detection)
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
                        f'[BASTION] Operation time range query: {query_start} ~ {query_end}'
                    )
                else:
                    # Use default range if no start time
                    time_range_query = {"range": {"timestamp": {"gte": f"now-{hours}h"}}}
            else:
                # Use default time range if no operation filter
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

                            # Extract MITRE technique
                            mitre_data = source.get('data', {}).get('mitre', {})
                            rule_mitre = source.get('rule', {}).get('mitre', {})
                            technique_id = None
                            tactic = None

                            # 1. Check data.mitre.id
                            if isinstance(mitre_data, dict):
                                technique_id = mitre_data.get('id')
                                tactic = mitre_data.get('tactic', [])
                                if isinstance(tactic, list) and tactic:
                                    tactic = tactic[0]

                            # 2. Check rule.mitre.id (extract first element if array)
                            if not technique_id and isinstance(rule_mitre, dict):
                                rule_mitre_id = rule_mitre.get('id')
                                if isinstance(rule_mitre_id, list) and rule_mitre_id:
                                    technique_id = rule_mitre_id[0]
                                elif isinstance(rule_mitre_id, str):
                                    technique_id = rule_mitre_id

                                # Also extract tactic
                                if not tactic:
                                    rule_mitre_tactic = rule_mitre.get('tactic')
                                    if isinstance(rule_mitre_tactic, list) and rule_mitre_tactic:
                                        tactic = rule_mitre_tactic[0]
                                    elif isinstance(rule_mitre_tactic, str):
                                        tactic = rule_mitre_tactic

                            # 3. Use rule ID mapping table
                            if not technique_id:
                                rule_id = str(source.get('rule', {}).get('id', ''))
                                technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                            # ⚠️ detected_techniques is only added after IntegrationEngine matching
                            # if technique_id:
                            #     detected_techniques.add(technique_id)

                            agent_id = source.get('agent', {}).get('id')
                            agent_os = wazuh_agent_os_map.get(agent_id, 'unknown')

                            # Extract detailed info fields
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
                                # Detailed info fields
                                'location': source.get('location'),
                                'full_log': source.get('full_log'),
                                'audit_command': audit_obj.get('command'),
                                'audit_exe': audit_obj.get('exe'),
                                'audit_type': audit_obj.get('type'),
                                'audit_cwd': audit_obj.get('cwd'),
                                'srcip': data_obj.get('srcip') if isinstance(data_obj, dict) else None,
                                'dstip': data_obj.get('dstip') if isinstance(data_obj, dict) else None,
                            })

            # 3-A. Apply detection_events matching info based on IntegrationEngine
            self.log.info(
                f"[BASTION DEBUG] Checking matching conditions: "
                f"has_integration_engine={hasattr(self, 'integration_engine')}, "
                f"integration_engine_exists={self.integration_engine is not None if hasattr(self, 'integration_engine') else False}, "
                f"filtered_ops_count={len(filtered_ops)}"
            )

            try:
                if hasattr(self, "integration_engine") and self.integration_engine and filtered_ops:
                    # 1) Build detection_events index: (rule_id, agent_id) -> [(event_dt, ev), ...]
                    index_by_rule_agent: Dict[tuple, List[tuple]] = {}

                    self.log.info(
                        f"[BASTION DEBUG] Starting matching - detection_events: {len(detection_events)}"
                    )

                    # 🔍 Debug: Print detection_events sample
                    if detection_events:
                        sample = detection_events[0]
                        self.log.info(
                            f"[BASTION DEBUG] Sample detection event: "
                            f"rule_id={sample.get('rule_id')}, "
                            f"technique_id={sample.get('technique_id')}, "
                            f"timestamp={sample.get('timestamp')}, "
                            f"agent_id={sample.get('agent_id')}"
                        )

                    # Build index (safe processing)
                    for ev in detection_events:
                        try:
                            ts = ev.get("timestamp")
                            rule_id = ev.get("rule_id")
                            agent_id = ev.get("agent_id") or ""

                            if not ts or not rule_id:
                                continue

                            # Parse timestamp (safe processing)
                            try:
                                ev_dt = date_parser.parse(ts)
                            except Exception as e:
                                self.log.debug(f'[BASTION] timestamp parsing failed: {ts}, error: {e}')
                                continue

                            # Convert to string for key (unify int to str, strip whitespace)
                            rule_key = str(rule_id).strip()
                            agent_key = str(agent_id).strip() if agent_id else ""
                            key = (rule_key, agent_key)

                            index_by_rule_agent.setdefault(key, []).append((ev_dt, ev))
                        except Exception as idx_err:
                            self.log.debug(f"[BASTION] Error building index (skip): {idx_err}")
                            continue

                    # Sorting helps with time difference calculations later
                    for key in index_by_rule_agent:
                        try:
                            index_by_rule_agent[key].sort(key=lambda x: x[0])
                        except Exception:
                            pass

                    self.log.info(
                        f"[BASTION DEBUG] Index building complete: {len(index_by_rule_agent)} keys"
                    )

                    # Consider events within ±5 minutes as the same (accounting for log transmission delay)
                    # Considering network delay, Wazuh processing time, Elasticsearch indexing time
                    # Actual tests show 3-4 minute delays, so setting with margin
                    THRESHOLD_SEC = 300
                    total_matched = 0

                    self.log.info(
                        f"[BASTION] Dashboard correlation starting: "
                        f"ops={len(filtered_ops)}, detections={len(detection_events)}"
                    )

                    for op in filtered_ops:
                        try:
                            self.log.info(
                                f"[BASTION DEBUG] IntegrationEngine.correlate() call: "
                                f"op={getattr(op, 'name', '')} ({getattr(op, 'id', '')})"
                            )
                            link_results = await self.integration_engine.correlate(op)

                            if not link_results:
                                self.log.info(f"[BASTION DEBUG] No link results for operation")
                                continue

                            self.log.info(
                                f"[BASTION DEBUG] IntegrationEngine result: {len(link_results)} links"
                            )

                            # 🔍 Print matching results for each link
                            for lr in link_results:
                                self.log.info(
                                    f"[BASTION DEBUG] Link: {lr.get('ability_name')} "
                                    f"(technique={lr.get('technique_id')}), "
                                    f"detected={lr.get('detected')}, "
                                    f"matches={lr.get('match_count')}"
                                )

                        except Exception as ce:
                            self.log.warning(
                                f"[BASTION] correlate failed (op={getattr(op, 'id', '')}): {ce}"
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

                                # ✅ Add technique_id from links with detected=True to detected_techniques
                                if lr.get("detected", False):
                                    tech_id = lr.get("technique_id")
                                    if tech_id:
                                        detected_techniques.add(tech_id)

                                # 🔍 Matching start debug (always output without condition)
                                if matches_list:
                                    self.log.info(
                                        f"[BASTION DEBUG] Processing {len(matches_list)} matches for link {link_id}"
                                    )

                                for idx, m in enumerate(matches_list):
                                    try:
                                        # 🔍 First match debug (always output without condition)
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

                                        # Parse timestamp
                                        try:
                                            m_dt = date_parser.parse(ts)
                                        except Exception:
                                            continue

                                        # Extract rule_id (safe processing, type unification)
                                        rule_id = m.get("rule.id") or m.get("rule_id")
                                        if not rule_id:
                                            continue

                                        # Unify rule_id to string (convert int to str)
                                        rule_key = str(rule_id).strip()

                                        # Extract agent_id (handle both dict/flat)
                                        agent = m.get("agent")
                                        if isinstance(agent, dict) and agent:
                                            agent_id = agent.get("id")
                                        else:
                                            agent_id = m.get("agent.id") or m.get("agent_id")

                                        # Unify agent_id to string
                                        agent_key = str(agent_id).strip() if agent_id else ""

                                        # Try matching (multiple key combinations - priority order)
                                        keys_to_try = []
                                        if agent_key:
                                            # Priority 1: Both rule_id and agent_id match
                                            keys_to_try.append((rule_key, agent_key))
                                        # Priority 2: Only rule_id matches (ignore agent_id)
                                        keys_to_try.append((rule_key, ""))

                                        matched_here = False
                                        match_details = None

                                        for key in keys_to_try:
                                            candidates = index_by_rule_agent.get(key, [])
                                            if not candidates:
                                                continue

                                            # Find the closest event
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
                                                # Match success
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
                                                    f"[BASTION DEBUG] ✓ Match success: "
                                                    f"rule_id={rule_key}, agent_id={agent_key}, "
                                                    f"time_diff={best_diff:.1f}s, link={link_id}"
                                                )
                                                break  # No need to try other keys for this match(m)
                                            elif best_ev is not None and best_diff is not None:
                                                # Candidates exist but time difference exceeded
                                                self.log.warning(
                                                    f"[BASTION] ✗ Time exceeded: "
                                                    f"rule_id={rule_key}, agent_id={agent_key}, "
                                                    f"time_diff={best_diff:.1f}s > {THRESHOLD_SEC}s, link={link_id}"
                                                )

                                        if not matched_here:
                                            # Log detailed info on match failure
                                            self.log.warning(
                                                f"[BASTION] ✗ Match failed: "
                                                f"rule_id={rule_key}, agent_id={agent_key}, "
                                                f"ts={ts}, link={link_id}, "
                                                f"candidates={sum(len(index_by_rule_agent.get(k, [])) for k in keys_to_try)}"
                                            )
                                    except Exception as match_err:
                                        self.log.debug(f"[BASTION] Individual match error (skip): {match_err}")
                                        continue
                            except Exception as link_err:
                                self.log.debug(f"[BASTION] Link processing error (skip): {link_err}")
                                continue

                    self.log.info(
                        f"[BASTION] dashboard correlation matched events: {total_matched}"
                    )
            except Exception as e:
                self.log.warning(f"[BASTION] Dashboard correlation application failed: {e}")
                import traceback
                traceback.print_exc()

            # 🔻 Matched detection events count (for KPI)
            matched_detection_events = [
                ev for ev in detection_events
                if ev.get('match_status') == 'matched'
            ]
            matched_detections_count = len(matched_detection_events)

            # 🔻 When op filter exists: Show only MATCHED events for that operation
            # 🔻 When op filter is "all": Show all Wazuh alerts (matched + unmatched)
            before = len(detection_events)
            if operation_id_filter:
                # When specific operation selected: Show only matched events
                detection_events = matched_detection_events
                self.log.info(
                    f"[BASTION] op_filter={operation_id_filter}: Showing MATCHED events only "
                    f"(total alerts={before}, matched detections={len(detection_events)})"
                )
            else:
                # all filter (no operation selected): Show all Wazuh alerts (matched + unmatched)
                # Events without match_status are set to 'unmatched'
                for ev in detection_events:
                    if not ev.get('match_status'):
                        ev['match_status'] = 'unmatched'
                self.log.info(
                    f"[BASTION] all filter: Showing all Wazuh alerts "
                    f"(total alerts={before}, matched detections={len(matched_detection_events)})"
                )

            # 4. Calculate Security Posture Score (Cymulate/AttackIQ style)
            agents = await self.data_svc.locate('agents')
            total_agents = len(agents)

            # Detection Rate calculation: Ratio of detected attacks to total attack attempts
            # operation_techniques is total link count, not set (unique techniques)
            total_attack_links = total_attack_steps  # Already calculated total link count

            # Calculate detected_links: Count of links with detected=True from IntegrationEngine
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

            # Coverage calculation: Detected links / Total links
            coverage = (
                detected_links / total_attack_links
                if total_attack_links > 0 else 0.0
            )

            detection_rate = round(coverage * 100, 1)
            security_score = int(detection_rate)

            # 🔍 Debug log
            self.log.info(
                f"[BASTION DEBUG] Detection Rate calculation: "
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

            # MTTD calculation (Mean Time To Detection)
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

            # Critical Gaps (number of simulated but undetected attacks)
            critical_gaps = total_attack_links - detected_links

            # Tactic Coverage
            all_tactics = set()
            for op in operations_data:
                for step in op.get('attack_steps', []):
                    if step.get('tactic'):
                        all_tactics.add(step['tactic'])

            tactic_coverage = len(all_tactics)

            # 🔍 Debug log
            self.log.info(
                f"[BASTION DEBUG] Tactic Coverage calculation: "
                f"operations_data={len(operations_data)}, "
                f"all_tactics={all_tactics}, "
                f"tactic_coverage={tactic_coverage}"
            )

            # 🔍 Log detection_events status right before API response
            if detection_events:
                self.log.info(
                    f"[BASTION DEBUG] Detection events sample before API return (first 3):"
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
                    # 🔻 Show only matched detection count (detections matching attacks)
                    'total_detections': matched_detections_count,
                    # 🔻 Added: Total Wazuh alerts count (for reference)
                    'total_alerts': before,
                    # 🔻 Added: Detected links count (IntegrationEngine-based)
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
                'detection_events': detection_events[:400],  # Only matched events, last 400
                'query_time': datetime.utcnow().isoformat()
            }

            self.log.info(
                f'[BASTION] Dashboard summary generation complete (operations: {len(operations_data)}, '
                f'detections: {len(detection_events)}, Score: {security_score}/{security_grade})'
            )
            return web.json_response(result)

        except Exception as e:
            self.log.error(f'[BASTION] Dashboard summary failed: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)


    async def get_technique_coverage(self, request: web.Request) -> web.Response:
        """
        MITRE ATT&CK Technique coverage analysis (for Heat Map)

        - Collect simulated technique statistics from Caldera operation links
        - Query alerts from Wazuh Indexer to count detected techniques
        """
        try:
            hours = int(request.query.get('hours', 24))
            self.log.info(f'[BASTION] Technique coverage analysis: last {hours} hours')

            now_utc = datetime.utcnow()
            cutoff_time = now_utc - timedelta(hours=hours)

            # 1. Aggregate "simulated" techniques based on Caldera operations & links
            technique_stats: Dict[str, Dict[str, Any]] = {}

            operations = await self.data_svc.locate('operations')
            for op in operations:
                if not op.start:
                    continue

                # Unify timezone-aware → naive for comparison
                op_start = op.start
                if isinstance(op_start, datetime):
                    if op_start.tzinfo:
                        op_start = op_start.replace(tzinfo=None)
                else:
                    # Pass through if string (can't filter)
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

            # 2. Aggregate only matched detections using IntegrationEngine
            if technique_stats and hasattr(self, 'integration_engine') and self.integration_engine:
                try:
                    # Run correlation for operations within time range
                    for op in operations:
                        if not op.start:
                            continue

                        op_start = op.start
                        if isinstance(op_start, datetime):
                            if op_start.tzinfo:
                                op_start = op_start.replace(tzinfo=None)

                        if isinstance(op_start, datetime) and op_start < cutoff_time:
                            continue

                        # Perform matching with IntegrationEngine
                        try:
                            link_results = await self.integration_engine.correlate(op)

                            # Extract technique ID from matched events
                            for link_result in link_results:
                                if link_result.get('detected', False):
                                    # Extract technique_id
                                    tech_id = link_result.get('technique_id')

                                    if tech_id and tech_id in technique_stats:
                                        # Count as 1 detected attack (even if multiple alerts match)
                                        technique_stats[tech_id]["detected"] += 1
                        except Exception as corr_err:
                            self.log.debug(f"[BASTION] Operation {op.id} correlation failed: {corr_err}")
                            continue

                except Exception as e:
                    self.log.warning(f"[BASTION] Detection aggregation with IntegrationEngine failed: {e}")

            # 3. Calculate detection rate / status
            techniques: List[Dict[str, Any]] = []
            for tech_id, stats in technique_stats.items():
                simulated = stats["simulated"]
                detected = stats["detected"]
                rate = (detected / simulated * 100.0) if simulated > 0 else 0.0

                if simulated == 0:
                    status = "not_simulated"  # gray
                elif detected == 0:
                    status = "gap"            # red
                elif rate < 80:
                    status = "partial"        # yellow
                else:
                    status = "complete"       # green

                techniques.append({
                    "id": tech_id,
                    "name": stats["name"],
                    "tactic": stats["tactic"],
                    "simulated": simulated,
                    "detected": detected,
                    "detection_rate": round(rate, 1),
                    "status": status,
                })

            # 4. Aggregate by Tactic
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
            self.log.error(f"[BASTION] Technique coverage query failed: {e}", exc_info=True)
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
        """Continuous Wazuh alert monitoring (background task)"""
        self.log.info(f'[BASTION] Continuous monitoring started (interval: {self.monitor_interval} seconds)')

        while True:
            try:
                await asyncio.sleep(self.monitor_interval)

                # TODO: Alert monitoring and automatic response logic
                self.log.debug('[BASTION] Monitoring cycle executed')

            except asyncio.CancelledError:
                self.log.info('[BASTION] Continuous monitoring stopped')
                break
            except Exception as e:
                self.log.error(f'[BASTION] Monitoring error: {e}')
                await asyncio.sleep(60)
