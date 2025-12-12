"""
BASTION Service - Core Logic for Caldera-Wazuh Integration
"""

import aiohttp
import asyncio
import logging
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from aiohttp import web
from dateutil import parser as date_parser

# loading integration_engine

try:
    from .integration_engine import IntegrationEngine
except Exception:
    from importlib import import_module
    IntegrationEngine = import_module('integration_engine').IntegrationEngine

class BASTIONService:
    """Caldera-Wazuh 통합 서비스"""

    # Wazuh Rule ID -> MITRE ATT&CK Technique Mapping
    # Manual mapping since default Wazuh rules lack MITRE tags
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

        # Processes
        '592': 'T1059',       # Process creation → Command and Scripting Interpreter
        '594': 'T1059',       # Process execution → Command and Scripting Interpreter
        
        # Reconnaissance
        '92604': 'T1057',
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

        # Wazuh Configuration
        self.manager_url = os.getenv('WAZUH_MANAGER_URL', config.get('wazuh_manager_url', 'https://localhost:55000'))
        self.indexer_url = os.getenv('WAZUH_INDEXER_URL', config.get('wazuh_indexer_url', 'https://localhost:9200'))
        self.username = os.getenv('WAZUH_USERNAME', config.get('wazuh_username', 'wazuh'))
        self.password = os.getenv('WAZUH_PASSWORD', config.get('wazuh_password', ''))
        
        self.indexer_username = os.getenv('WAZUH_INDEXER_USERNAME', config.get('indexer_username', 'admin'))
        self.indexer_password = os.getenv('WAZUH_INDEXER_PASSWORD', config.get('indexer_password', ''))
        
        self.verify_ssl = config.get('verify_ssl', False)
        if os.getenv('WAZUH_VERIFY_SSL'):
            self.verify_ssl = os.getenv('WAZUH_VERIFY_SSL').lower() in ('true', '1', 'yes')
        self.monitor_interval = config.get('alert_query_interval', 300)
        # Initialize IntegrationEngine
        try:
            self.log.info("[BASTION] Starting IntegrationEngine initialization...")
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

        # State Management
        self.token = None
        self.token_expiry = None
        self.last_alert_time = datetime.utcnow()
        self.is_authenticated = False

        

    async def authenticate(self):
        """Authenticate with Wazuh Manager API"""
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
            self.log.error(f'[BASTION] Failed to connect to Wazuh Manager: {e}')
            self.log.error(f'[BASTION] Please check if {self.manager_url} is correct')
            raise
        except asyncio.TimeoutError:
            self.log.error('[BASTION] Wazuh API connection timeout (10s)')
            raise
        except Exception as e:
            self.log.error(f'[BASTION] Wazuh authentication error: {e}')
            raise

    async def _ensure_authenticated(self):
        """Check token validity and re-authenticate if needed"""
        if not self.token or not self.token_expiry:
            await self.authenticate()
        elif datetime.utcnow() >= self.token_expiry:
            self.log.info('[BASTION] Token expired, re-authenticating...')
            await self.authenticate()

    async def get_recent_alerts(self, request: web.Request) -> web.Response:
        """
        Retrieve recent Wazuh alerts
        
        Query Parameters:
            hours: Time range to query (default: 1 hour)
            min_level: Minimum severity level (default: 7)
        """
        try:
            hours = int(request.query.get('hours', 1))
            min_level = int(request.query.get('min_level', 7))

            self.log.info(f'[BASTION] Alert query requested: Recent {hours} hours, Level >= {min_level}')

            # OpenSearch Query
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
                # Authenticate with Wazuh Indexer
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
                            

                            # 1. Check MITRE data directly from the alert
                            # Extract technique ID from rule.mitre.id field
                            rule_data = source.get('rule', {})
                            mitre_data = rule_data.get('mitre', {})
                            technique_id = None

                            if isinstance(mitre_data, dict) and 'id' in mitre_data:
                                # mitre.id can be a list, so use the first value
                                mitre_ids = mitre_data['id']
                                if isinstance(mitre_ids, list) and len(mitre_ids) > 0:
                                    technique_id = mitre_ids[0]
                                elif isinstance(mitre_ids, str):
                                    technique_id = mitre_ids

                            # 2. Use Rule ID mapping table if no MITRE data exists
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

                        self.log.info(f'[BASTION] {len(alerts)} alerts retrieved successfully')
                        return web.json_response(result)
                    else:
                        error_text = await resp.text()
                        self.log.error(f'[BASTION] Indexer query failed: {error_text}')
                        return web.json_response({
                            'success': False,
                            'error': f'Indexer query failed: HTTP {resp.status}'
                        }, status=500)

        except Exception as e:
            self.log.error(f'[BASTION] Failed to retrieve alerts: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def correlate_operation(self, request: web.Request) -> web.Response:
        """
        Correlation analysis between Caldera operations and Wazuh alerts
        (Match operation <-> detection based on IntegrationEngine)
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

            # 1) Retrieve Caldera operation
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
            except Exception:
                duration_seconds = 0

            # 3) Construct list of MITRE techniques & abilities executed in operation (safe processing)
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
                    self.log.debug(f'[BASTION] Error processing link (skipped): {link_err}')
                    continue

            self.log.info(f'[BASTION] Operation executed techniques: {operation_techniques}')

            # 4) Detection matching per link using IntegrationEngine
            #    Uses index, time_window_sec, and field mappings defined in conf/default.yml
            link_results = []
            try:
                link_results = await self.integration_engine.correlate(operation)
            except Exception as corr_err:
                self.log.error(f'[BASTION] IntegrationEngine correlate failed: {corr_err}')
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

            # 5) Calculate detected Techniques / matched alert list (safe processing)
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
                                # Organize field names for use in Vue table
                                'timestamp': m.get('@timestamp') or m.get('timestamp'),
                                'rule_id': m.get('rule.id') or m.get('rule_id'),
                                'rule_level': m.get('level') or m.get('rule_level'),
                                'description': m.get('description', ''),
                                'agent_name': m.get('agent.name') or m.get('agent_name'),
                                'agent_id': m.get('agent.id') or m.get('agent_id'),
                                'technique_id': tech or m.get('mitre.id') or m.get('technique_id'),
                                # Also provide which link/ability triggered the detection
                                'link_id': link_id,
                                'ability_name': ability_name,
                                'match_status': 'MATCHED',
                                'match_source': 'wazuh'
                            })
                        except Exception as alert_err:
                            self.log.debug(f'[BASTION] Error processing alert (skipped): {alert_err}')
                            continue
                except Exception as lr_err:
                    self.log.debug(f'[BASTION] Error processing link_result (skipped): {lr_err}')
                    continue

            # 6) Calculate matching and detection rates (maintain existing structure)
            matched_techniques = operation_techniques.intersection(detected_techniques)
            undetected_techniques = operation_techniques - detected_techniques

            detection_rate = 0.0
            if operation_techniques:
                detection_rate = len(matched_techniques) / len(operation_techniques)

            # 7) Generate final correlation result (keep existing response schema + add links)
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
                # Provide raw results per link for potential frontend detail usage
                'links': link_results,
                # Keep existing alerts_matched (for Vue Detection Table)
                'alerts_matched': alerts_matched,
                'total_alerts': len(alerts_matched)
            }

            self.log.info(
                f'[BASTION] Correlation analysis complete (IntegrationEngine): '
                f'Detection Rate {detection_rate:.1%}, links={len(link_results)}, alerts={len(alerts_matched)}'
            )

            return web.json_response(correlation_result)

        except Exception as e:
            self.log.error(f'[BASTION] Correlation analysis failed: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)


    async def generate_detection_report(self, request: web.Request) -> web.Response:
        """Generate Detection Coverage Report"""
        try:
            # TODO: Implementation required
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
            # TODO: Implementation required
            return web.json_response({
                'success': True,
                'message': 'Adaptive operation not implemented yet'
            })

        except Exception as e:
            self.log.error(f'[BASTION] Failed to create adaptive operation: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def get_agents_with_detections(self, request: web.Request) -> web.Response:
        """
        List Caldera Agents + Wazuh Agent Mapping + Recent Detections

        Query Parameters:
            hours: Time range to query (default: 1 hour)
            operation_id: Specific operation ID filter (optional)
            os_filter: OS platform filter (optional: Windows, Linux, macOS)
            search: Search term (optional)
        """
        try:
            hours = int(request.query.get('hours', 1))
            operation_id_filter = request.query.get('operation_id', '').strip()
            raw_os = request.query.get('os_filter') or request.query.get('os')
            os_filter = (raw_os or '').strip().lower()
            search_query = request.query.get('search', '').strip().lower()

            self.log.info(f'[BASTION] Agents query requested (Recent {hours}h detections, op_filter={operation_id_filter}, os={os_filter}, search={search_query})')

            # 1. Retrieve Wazuh Agents (indexed by ID)
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
                            self.log.info(f'[BASTION] {len(wazuh_agents_by_id)} Agents retrieved')
            except Exception as e:
                self.log.warning(f'[BASTION] Failed to retrieve Agents: {e}')

            # 2. Retrieve Caldera Agents
            agents = await self.data_svc.locate('agents')

            agents_data = []
            for agent in agents:
                # Determine agent alive status (timezone safe)
                alive = False
                if agent.last_seen:
                    try:
                        # Handle timezone-aware datetime
                        last_seen = agent.last_seen.replace(tzinfo=None) if agent.last_seen.tzinfo else agent.last_seen
                        alive = (datetime.utcnow() - last_seen).total_seconds() < 300  # 5분 이내
                    except Exception:
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
                    'attack_steps_count': 0,  # Week 11: Attack steps count per Agent
                    'detections_count': 0     # Week 11: Detections count per Agent
                }

                # Wazuh Agent Matching
                wazuh_agent = None
                wazuh_agent_id = None

                # 1) Priority: Find wazuh.agent.id in Agent links facts
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
                            f'Mapped based on host="{agent.host}" -> '
                            f'{wazuh_agent_id} ({fallback.get("name")})'
                        )

                # 3) Log warning if both failed
                if not wazuh_agent_id:
                    self.log.warning(
                        f'[BASTION DEBUG] Agent {agent.paw}: '
                        f'Wazuh mapping failed (both facts/host mismatch)'
                    )


                # Retrieve Wazuh agent info
                if wazuh_agent_id:
                    wazuh_agent = wazuh_agents_by_id.get(wazuh_agent_id)
                    if not wazuh_agent:
                        self.log.warning(f'[BASTION] Agent {agent.paw}: Wazuh ID {wazuh_agent_id} does not exist')

                agent_info['wazuh_matched'] = wazuh_agent is not None
                agent_info['wazuh_agent'] = wazuh_agent if wazuh_agent else None

                # 2. Retrieve recent Wazuh detections for each Agent (only if matched)
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

                                        # 1. Check MITRE data directly from the alert
                                        mitre_data = source.get('data', {}).get('mitre', {})
                                        technique_id = mitre_data.get('id') if isinstance(mitre_data, dict) else None

                                        # 2. Use Rule ID mapping table if no MITRE data exists
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
                        self.log.warning(f'[BASTION] Failed to retrieve detections for Agent {agent.paw}: {e}')
                        # Return agent info even if error occurs

                # 1. Detections count (recent_detections 길이)
                agent_info['detections_count'] = len(agent_info['recent_detections'])

                # 2. Attack steps count (number of links for the agent)
                try:
                    if hasattr(agent, 'links') and agent.links:
                        # If operation filter exists, count links only for that operation
                        if operation_id_filter:
                            all_operations = await self.data_svc.locate('operations')
                            for op in all_operations:
                                if op.id == operation_id_filter:
                                    # Count links for current agent in this operation's chains
                                    for chain in op.chain:
                                        if hasattr(chain, 'paw') and chain.paw == agent.paw:
                                            agent_info['attack_steps_count'] += 1
                                    break
                        else:
                            # Count all links
                            agent_info['attack_steps_count'] = len([link for link in agent.links if link.finish])
                except Exception as e:
                    self.log.warning(f'[BASTION] Failed to calculate attack steps for Agent {agent.paw}: {e}')

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

                # Apply Operation Filter (include only agents participated in the operation)
                if operation_id_filter:
                    all_operations = await self.data_svc.locate('operations')
                    operation_match = False
                    for op in all_operations:
                        if op.id == operation_id_filter:
                            # Check if current agent is in this operation's agents
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

            self.log.info(f'[BASTION] {len(agents_data)} Agents retrieved successfully')
            return web.json_response(result)

        except Exception as e:
            self.log.error(f'[BASTION] Failed to retrieve Agents: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def health_check(self, request: web.Request) -> web.Response:
        """Check plugin and Wazuh connection health"""
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
        Retrieve Dashboard Integrated Data (KPI, Operations, Tactic Coverage, Timeline)

        Query Parameters:
            hours: Time range (default: 24h)
            min_level: Minimum severity level (default: 5)
            operation_id: Specific operation ID filter (optional)
            os_filter: OS platform filter (optional: Windows, Linux, macOS)
            search: Search term (optional)
        """
        try:
            hours = int(request.query.get('hours', 24))
            min_level = int(request.query.get('min_level', 5))
            operation_id_filter = request.query.get('operation_id', '').strip()
            raw_os = request.query.get('os_filter') or request.query.get('os')
            os_filter = (raw_os or '').strip().lower()
            search_query = request.query.get('search', '').strip().lower()

            self.log.info(
                f'[BASTION] Dashboard summary query: Recent {hours} hours '
                f'(op_filter={operation_id_filter}, os_filter={os_filter}, search={search_query})'
            )

            # 1. Retrieve Operations (Caldera)
            all_operations = await self.data_svc.locate('operations')
            all_agents = await self.data_svc.locate('agents')  # Retrieve all agents

            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            operations_data = []
            filtered_ops: List[Any] = []
            total_attack_steps = 0
            operation_techniques = set()  # Techniques executed in all operations

            self.log.error(
                f'[BASTION DEBUG] Total operations: {len(all_operations)}, cutoff_time: {cutoff_time}'
            )

            for op in all_operations:
                # 1) Operation ID Filter
                if operation_id_filter and op.id != operation_id_filter:
                    continue

                # 2) Time Filter: Apply only if operation_id_filter is absent
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
                    # If link.finish is datetime, convert to isoformat; if string, use as is
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
                        'paw': link.paw  # Add Agent ID (for OS filter)
                    })

                    if ability.technique_id:
                        op_techniques.add(ability.technique_id)
                        operation_techniques.add(ability.technique_id)

                total_attack_steps += len(attack_steps)

                # Map Agent PAWs and platforms
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

                    # 1. Find in all_agents
                    for agent in all_agents:
                        if agent.paw == paw:
                            agent_platforms[paw] = agent.platform
                            agent_paws.append(paw)
                            found = True
                            break

                    # 2. Find in op.agents (if not in all_agents)
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

                # Apply OS Filter (Include if any of agent_platforms match)
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

                # Apply Search Filter (Search Operation name, Agent PAW, Technique)
                if search_query:
                    search_match = False
                    # Search Operation Name
                    if search_query in (op.name or '').lower():
                        search_match = True
                    # Search Agent PAW
                    for paw in agent_paws:
                        if search_query in (paw or '').lower():
                            search_match = True
                            break
                    # Search Technique ID
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

            # 2. Retrieve Wazuh Agent Info (agent_id -> OS mapping)
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

                        # Retrieve all Wazuh agents
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

            # 3. Retrieve Wazuh Detection Events
            # If operation filter exists, query within that operation's execution time range
            time_range_query = {}

            if operation_id_filter and filtered_ops:
                # Calculate start/end time range of filtered operations
                op_start_times = []
                op_end_times = []

                for op in filtered_ops:
                    if op.start:
                        op_start = op.start.replace(tzinfo=None) if op.start.tzinfo else op.start
                        op_start_times.append(op_start)

                    if op.finish:
                        op_end = op.finish.replace(tzinfo=None) if op.finish.tzinfo else op.finish
                        op_end_times.append(op_end)

                if op_start_times:
                    earliest_start = min(op_start_times)
                    # Query from 30 seconds before operation start (include pre-detection)
                    query_start = (earliest_start - timedelta(seconds=30)).isoformat()

                    if op_end_times:
                        latest_end = max(op_end_times)
                    else:
                        # Use current time if no finish time
                        latest_end = datetime.utcnow()

                    # Query until 30 seconds after operation end (include delayed detection)
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
                    "agent.id", "agent.name", "rule.mitre.technique", "rule.mitre.id"
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

                            # 2. Check rule.mitre.id (extract first element if list)
                            if not technique_id and isinstance(rule_mitre, dict):
                                rule_mitre_id = rule_mitre.get('id')
                                if isinstance(rule_mitre_id, list) and rule_mitre_id:
                                    technique_id = rule_mitre_id[0]
                                elif isinstance(rule_mitre_id, str):
                                    technique_id = rule_mitre_id

                                # Extract tactic as well
                                if not tactic:
                                    rule_mitre_tactic = rule_mitre.get('tactic')
                                    if isinstance(rule_mitre_tactic, list) and rule_mitre_tactic:
                                        tactic = rule_mitre_tactic[0]
                                    elif isinstance(rule_mitre_tactic, str):
                                        tactic = rule_mitre_tactic

                            # 3. Use Rule ID mapping table
                            if not technique_id:
                                rule_id = str(source.get('rule', {}).get('id', ''))
                                technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                            if technique_id:
                                detected_techniques.add(technique_id)

                            agent_id = source.get('agent', {}).get('id')
                            agent_os = wazuh_agent_os_map.get(agent_id, 'unknown')

                            detection_events.append({
                                'doc_id': doc_id,
                                'timestamp': ts,
                                'rule_id': source.get('rule', {}).get('id'),
                                'rule_level': source.get('rule', {}).get('level'),
                                'description': source.get('rule', {}).get('description'),
                                'agent_name': source.get('agent', {}).get('name'),
                                'agent_id': agent_id,
                                'agent_os': agent_os,
                                'technique_id': technique_id,
                                'tactic': tactic,
                                'match_status': 'unmatched',
                                'attack_step_id': None,
                                'match_source': 'wazuh',
                                'opId': None,
                            })

            # 3-A. Reflect match info to detection_events based on IntegrationEngine
            self.log.info(
                f"[BASTION DEBUG] Check match conditions: "
                f"has_integration_engine={hasattr(self, 'integration_engine')}, "
                f"integration_engine_exists={self.integration_engine is not None if hasattr(self, 'integration_engine') else False}, "
                f"filtered_ops_count={len(filtered_ops)}"
            )

            try:
                if hasattr(self, "integration_engine") and self.integration_engine and filtered_ops:
                    # 1) Build detection_events index: (rule_id, agent_id) -> [(event_dt, ev), ...]
                    index_by_rule_agent: Dict[tuple, List[tuple]] = {}

                    self.log.info(
                        f"[BASTION DEBUG] Match start - detection_events: {len(detection_events)}"
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
                            except Exception:
                                continue

                            # Convert to string for key (unify int to str, strip whitespace)
                            rule_key = str(rule_id).strip()
                            agent_key = str(agent_id).strip() if agent_id else ""
                            key = (rule_key, agent_key)

                            index_by_rule_agent.setdefault(key, []).append((ev_dt, ev))
                        except Exception as idx_err:
                            self.log.debug(f"[BASTION] Error building index (skip): {idx_err}")
                            continue

                    # Sorting makes time difference calculation easier later
                    for key in index_by_rule_agent:
                        try:
                            index_by_rule_agent[key].sort(key=lambda x: x[0])
                        except Exception:
                            pass

                    self.log.info(
                        f"[BASTION DEBUG] Index build complete: {len(index_by_rule_agent)} keys"
                    )

                    # Consider same event if within +/- 5 minutes (considering log delay)
                    # Consider network delay, Wazuh processing time, Elasticsearch indexing time
                    # Actual test shows 3-4 mins delay, so set with margin
                    THRESHOLD_SEC = 300
                    total_matched = 0

                    self.log.info(
                        f"[BASTION] Start dashboard correlation: "
                        f"ops={len(filtered_ops)}, detections={len(detection_events)}"
                    )

                    for op in filtered_ops:
                        try:
                            self.log.info(
                                f"[BASTION DEBUG] Calling IntegrationEngine.correlate(): "
                                f"op={getattr(op, 'name', '')} ({getattr(op, 'id', '')})"
                            )
                            link_results = await self.integration_engine.correlate(op)

                            if not link_results:
                                self.log.info(f"[BASTION DEBUG] No link results for operation")
                                continue

                            self.log.info(
                                f"[BASTION DEBUG] IntegrationEngine result: {len(link_results)} links"
                            )

                            # 🔍 Print match result for each link
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

                                # 🔍 Match start debug (always print)
                                if matches_list:
                                    self.log.info(
                                        f"[BASTION DEBUG] Processing {len(matches_list)} matches for link {link_id}"
                                    )

                                for idx, m in enumerate(matches_list):
                                    try:
                                        # 🔍 First match debug (always print)
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

                                        # Extract rule_id (safe processing, unify type)
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

                                        # Try matching (Combination of keys - Priority order)
                                        keys_to_try = []
                                        if agent_key:
                                            # Priority 1: Both rule_id + agent_id match
                                            keys_to_try.append((rule_key, agent_key))
                                        # Priority 2: rule_id matches (ignore agent_id)
                                        keys_to_try.append((rule_key, ""))

                                        matched_here = False
                                        match_details = None

                                        for key in keys_to_try:
                                            candidates = index_by_rule_agent.get(key, [])
                                            if not candidates:
                                                continue

                                            # Find one closest event
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
                                                total_matched += 1
                                                matched_here = True
                                                match_details = f"diff={best_diff:.1f}s, key={key}"

                                                self.log.info(
                                                    f"[BASTION DEBUG] ✓ Match success: "
                                                    f"rule_id={rule_key}, agent_id={agent_key}, "
                                                    f"time_diff={best_diff:.1f}s, link={link_id}"
                                                )
                                                break  # This match(m) doesn't need to be checked with other keys
                                            elif best_ev is not None and best_diff is not None:
                                                # Candidate exists but time difference exceeded
                                                self.log.warning(
                                                    f"[BASTION] ✗ Time out: "
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
                self.log.warning(f"[BASTION] Dashboard correlation update failed: {e}")
                import traceback
                traceback.print_exc()

            # 🔻 When op filter exists: Show all detections within operation time range (regardless of MATCHED status)
            # Allows user to see which detections matched and which didn't
            if operation_id_filter:
                before = len(detection_events)
                # Keep all detection events (already filtered by time range query)
                # match_status column allows distinguishing MATCHED/UNMATCHED
                self.log.info(
                    f"[BASTION] Applying operation_id_filter={operation_id_filter}: "
                    f"Show all detections within time range (total: {len(detection_events)}, "
                    f"matched: {sum(1 for ev in detection_events if ev.get('match_status') == 'matched')})"
                )

            # 4. Calculate Security Posture Score (Cymulate/AttackIQ style)
            agents = await self.data_svc.locate('agents')
            total_agents = len(agents)

            matched_techniques = operation_techniques.intersection(detected_techniques)
            coverage = (
                len(matched_techniques) / len(operation_techniques)
                if operation_techniques else 0.0
            )

            detection_rate = round(coverage * 100, 1)
            security_score = int(detection_rate)

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

            # Critical Gaps (Number of techniques simulated but not detected)
            critical_gaps = len(operation_techniques - detected_techniques)

            # Tactic Coverage
            all_tactics = set()
            for op in operations_data:
                for step in op.get('attack_steps', []):
                    if step.get('tactic'):
                        all_tactics.add(step['tactic'])
            tactic_coverage = len(all_tactics)

            # 🔍 Log detection_events status right before API response
            if detection_events:
                self.log.info(
                    f"[BASTION DEBUG] detection_events sample before API return (first 3):"
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
                    'total_detections': len(detection_events),
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
                'detection_events': detection_events[:400],  # Recent 400 only
                'query_time': datetime.utcnow().isoformat()
            }

            self.log.info(
                f'[BASTION] Dashboard summary created (Ops: {len(operations_data)}, '
                f'Detections: {len(detection_events)}, Score: {security_score}/{security_grade})'
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
        MITRE ATT&CK Technique Coverage Analysis (For Heat Map)

        - Collect simulated technique stats from Caldera operation links
        - Count detected techniques by querying Wazuh Indexer alerts
        - Supports filters: operation_id, os_filter, search
        """
        try:
            hours = int(request.query.get('hours', 24))
            operation_id = request.query.get('operation_id')
            os_filter = request.query.get('os_filter')
            search = request.query.get('search', '').lower()

            self.log.info(
                f'[BASTION] Technique coverage analysis: Last {hours} hours, '
                f'operation_id={operation_id}, os_filter={os_filter}, search={search}'
            )

            now_utc = datetime.utcnow()
            cutoff_time = now_utc - timedelta(hours=hours)

            # Build agent platform map and filter by OS
            all_agents = await self.data_svc.locate('agents')
            agent_platforms = {}
            filtered_agent_paws = set()

            for agent in all_agents:
                platform = getattr(agent, 'platform', 'unknown')
                agent_platforms[agent.paw] = platform.lower()

                # Apply OS filter
                if os_filter and os_filter.lower() != 'all':
                    if os_filter.lower() not in platform.lower():
                        continue

                # Apply search filter to agent
                if search:
                    agent_host = getattr(agent, 'host', '') or ''
                    agent_user = getattr(agent, 'username', '') or ''
                    if search not in agent_host.lower() and search not in agent_user.lower() and search not in agent.paw.lower():
                        continue

                filtered_agent_paws.add(agent.paw)

            # 1. Aggregate "simulated" techniques based on Caldera operations & links
            technique_stats: Dict[str, Dict[str, Any]] = {}

            operations = await self.data_svc.locate('operations')
            for op in operations:
                if not op.start:
                    continue

                # Filter by operation_id if specified
                if operation_id and operation_id != 'all' and op.id != operation_id:
                    continue

                # Unify as naive for comparison (timezone-aware -> naive)
                op_start = op.start
                if isinstance(op_start, datetime):
                    if op_start.tzinfo:
                        op_start = op_start.replace(tzinfo=None)
                else:
                    # Pass as is if string (cannot filter)
                    pass

                if isinstance(op_start, datetime) and op_start < cutoff_time:
                    continue

                if not hasattr(op, 'chain') or not op.chain:
                    continue

                for link in op.chain:
                    # Apply OS filter - skip if agent doesn't match
                    link_paw = getattr(link, 'paw', None)
                    if os_filter and os_filter.lower() != 'all':
                        agent_platform = agent_platforms.get(link_paw, '')
                        if os_filter.lower() not in agent_platform:
                            continue

                    ability = getattr(link, 'ability', None)
                    if not ability or not ability.technique_id:
                        continue

                    tech_id = ability.technique_id
                    tech_name = ability.technique_name or tech_id
                    tactic = ability.tactic or 'unknown'

                    # Apply search filter to technique
                    if search:
                        if (search not in tech_id.lower() and
                            search not in tech_name.lower() and
                            search not in tactic.lower()):
                            continue

                    if tech_id not in technique_stats:
                        technique_stats[tech_id] = {
                            'id': tech_id,
                            'name': tech_name,
                            'tactic': tactic,
                            'simulated': 0,
                            'detected': 0,
                        }
                    technique_stats[tech_id]['simulated'] += 1

            # 2. Aggregate "detected" techniques by querying Wazuh alerts
            if technique_stats:
                try:
                    timeout = aiohttp.ClientTimeout(total=30)
                    connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

                    # Query alerts for the last N hours
                    query = {
                        "query": {
                            "bool": {
                                "must": [
                                    {"range": {"timestamp": {"gte": f"now-{hours}h"}}}
                                ]
                            }
                        },
                        "size": 1000,
                        "_source": [
                            "@timestamp",
                            "timestamp",
                            "rule.id",
                            "rule.level",
                            "rule.description",
                            "agent.id",
                            "agent.name",
                            "data.mitre",   
                            "data.mitre.id",
                            "data.mitre.tactic",
                            "rule.mitre.technique", 
                            "rule.mitre.id",
                        ]
                    }

                    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                        auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                        async with session.post(
                            f"{self.indexer_url}/wazuh-alerts-*/_search",
                            json=query,
                            auth=auth,
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                hits = data.get("hits", {}).get("hits", [])

                                for hit in hits:
                                    src = hit.get("_source", {})
                                    mitre = src.get("data", {}).get("mitre", {})

                                    tech_id = None

                                    # 1) Use data.mitre.id directly
                                    if isinstance(mitre, dict):
                                        tech_id = mitre.get("id")

                                    # 2) Map rule.id -> RULE_MITRE_MAPPING if missing
                                    if not tech_id:
                                        rule_id = str(src.get("rule", {}).get("id", ""))
                                        tech_id = self.RULE_MITRE_MAPPING.get(rule_id)

                                    if tech_id and tech_id in technique_stats:
                                        technique_stats[tech_id]["detected"] += 1
                            else:
                                err = await resp.text()
                                self.log.warning(
                                    f"[BASTION] Indexer query for Technique coverage failed: HTTP {resp.status} {err}"
                                )
                except Exception as e:
                    # Allow screen display even without detection stats
                    self.log.warning(f"[BASTION] Wazuh alerts query failed (proceeding with detection=0): {e}")

            # 3. Calculate Detection rate / status
            # NOTE: Detection rate should be based on whether the technique was detected,
            # not on the raw count of alerts. Each simulated attack should count as 1,
            # and if at least 1 alert matched, that counts as 1 detection.
            # Rate = min(detected_count, simulated_count) / simulated_count * 100
            # This caps the rate at 100% maximum.
            techniques: List[Dict[str, Any]] = []
            for tech_id, stats in technique_stats.items():
                simulated = stats["simulated"]
                detected_raw = stats["detected"]
                # Cap detected count at simulated count to prevent >100% rates
                detected_capped = min(detected_raw, simulated) if simulated > 0 else 0
                rate = (detected_capped / simulated * 100.0) if simulated > 0 else 0.0

                if simulated == 0:
                    status = "not_simulated"  # Gray
                elif detected_raw == 0:
                    status = "gap"            # Red
                elif rate < 80:
                    status = "partial"        # Yellow
                else:
                    status = "complete"       # Green

                techniques.append({
                    "id": tech_id,
                    "name": stats["name"],
                    "tactic": stats["tactic"],
                    "simulated": simulated,
                    "detected": detected_capped,  # Use capped value for display
                    "detected_raw": detected_raw,  # Keep raw count for debugging
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
                # Coverage is already using capped detected values, but ensure max 100%
                coverage = (detected / total * 100.0) if total > 0 else 0.0
                t["coverage"] = round(min(coverage, 100.0), 1)

            total_simulated = sum(t["simulated"] for t in techniques)
            total_detected = sum(t["detected"] for t in techniques)
            # Ensure overall rate never exceeds 100%
            overall_rate = (total_detected / total_simulated * 100.0) if total_simulated > 0 else 0.0
            overall_rate = min(overall_rate, 100.0)

            summary = {
                "total_techniques": len(techniques),
                "total_simulated": total_simulated,
                "total_detected": total_detected,
                "overall_detection_rate": round(overall_rate, 1),
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
            self.log.error(f"[BASTION] Failed to query Technique coverage: {e}", exc_info=True)
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
        """Continuous Wazuh alert monitoring (Background task)"""
        self.log.info(f'[BASTION] Continuous monitoring started (interval: {self.monitor_interval}s)')

        while True:
            try:
                await asyncio.sleep(self.monitor_interval)

                # TODO: Alert monitoring and automated response logic
                self.log.debug('[BASTION] Monitoring cycle executed')

            except asyncio.CancelledError:
                self.log.info('[BASTION] Continuous monitoring stopped')
                break
            except Exception as e:
                self.log.error(f'[BASTION] Monitoring error: {e}')
                await asyncio.sleep(60)
