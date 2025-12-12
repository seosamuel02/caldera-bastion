import os
import yaml
import asyncio
from datetime import datetime, timedelta, timezone

try:
    from opensearchpy import OpenSearch
except Exception:
    OpenSearch = None

try:
    from elasticsearch import Elasticsearch
except Exception:
    Elasticsearch = None


CONFIG_CANDIDATES = [
    os.path.join(os.path.dirname(__file__), 'conf', 'default.yml'),
    os.path.join(os.getcwd(), 'conf', 'default.yml')
]


def _to_dt(value):
    """value(str/int/float/datetime) -> timezone-aware UTC datetime | None"""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        s = value.strip()
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        try:
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


def _iso(dt):
    if dt is None:
        return None

    # If UNIX timestamp, convert to datetime
    if isinstance(dt, (int, float)):
        dt = datetime.fromtimestamp(dt, tz=timezone.utc)

    # If naive datetime, set to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    # Generate ISO8601
    text = dt.isoformat()

    # "+00:00" → "Z"
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"

    return text


class IntegrationEngine:
    def __init__(self, overrides: dict | None = None, rule_mitre_mapping: dict | None = None):
        self.config = self._load_settings()
        if overrides:
            # shallow override for top-level known keys
            self.config.update(overrides)

        self.wazuh = self.config.get('wazuh', {})
        self.match = self.config.get('match', {})
        self.client = self._build_client()

        # Debugging mode
        self.debug = self.config.get('debug', False)

        # Rule ID -> MITRE Technique mapping (reverse mapping creation)
        self.rule_mitre_mapping = rule_mitre_mapping or {}
        self.technique_to_rules = {}  # MITRE Technique -> Rule IDs reverse mapping
        if self.rule_mitre_mapping:
            for rule_id, technique_id in self.rule_mitre_mapping.items():
                if technique_id not in self.technique_to_rules:
                    self.technique_to_rules[technique_id] = []
                self.technique_to_rules[technique_id].append(str(rule_id))

    # ------------------
    # Config / Client
    # ------------------
    def _load_settings(self) -> dict:
        for path in CONFIG_CANDIDATES:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
        return {}

    def _build_client(self):
        # support both nested (wazuh.*) and legacy flat keys
        host = self.wazuh.get('host') or self.config.get('host', 'localhost')
        port = int(self.wazuh.get('port') or self.config.get('port', 9200))
        scheme = (self.wazuh.get('scheme') or ('https' if self.config.get('ssl') else 'http') or 'http')
        verify = bool(self.wazuh.get('verify_ssl', self.config.get('verify_certs', True)))
        username = self.wazuh.get('username') or self.config.get('username')
        password = self.wazuh.get('password') or self.config.get('password')

        # Default kwargs
        kwargs = {
            'verify_certs': verify,
            'ssl_show_warn': False,
            'timeout': 30,
            'max_retries': 2,
            'retry_on_timeout': True,
        }

        # Host definition: ES prefers scheme included in hosts, OS also accepts it
        hosts = [{'host': host, 'port': port, 'scheme': scheme}]
        kwargs['hosts'] = hosts

        # SSL configuration (relax verification if self-signed allowed)
        if scheme == 'https':
            kwargs['use_ssl'] = True
            if not verify:
                # Required for some versions
                kwargs['ssl_assert_hostname'] = False
                kwargs['ssl_assert_fingerprint'] = None
        else:
            kwargs['use_ssl'] = False

        # Authentication (support both client types)
        if username:
            kwargs['http_auth'] = (username, password)
            kwargs['basic_auth'] = (username, password)

        if OpenSearch is not None:
            return OpenSearch(**kwargs)
        if Elasticsearch is not None:
            return Elasticsearch(**kwargs)
        raise RuntimeError('Neither opensearch-py nor elasticsearch client is installed')

    # ------------------
    # Operation Events
    # ------------------
    def _event_from_link(self, link) -> dict:
        """Convert link information to event dictionary (safe processing)"""
        try:
            ability = getattr(link, 'ability', None)
            technique_id = getattr(ability, 'technique_id', None) if ability else None
            ability_name = getattr(ability, 'name', '') if ability else ''
            ts_dt = getattr(link, 'finish', None) or getattr(link, 'start', None) or getattr(link, 'decide', None)
            command = getattr(link, 'command', None)
            pid = getattr(link, 'pid', None)

            # Handle timestamp safely
            timestamp = None
            if ts_dt:
                try:
                    if hasattr(ts_dt, 'timestamp'):
                        timestamp = ts_dt.timestamp()
                    elif isinstance(ts_dt, (int, float)):
                        timestamp = float(ts_dt)
                except Exception:
                    timestamp = None

            return {
                'link_id': str(getattr(link, 'id', '')),
                'ability_name': ability_name or '',
                'technique_id': technique_id or '',
                'executed_at': _iso(ts_dt),
                'timestamp': timestamp,
                'command': command.decode('utf-8', errors='ignore') if isinstance(command, (bytes, bytearray)) else (command or ''),
                'pid': pid,
            }
        except Exception as e:
            # Return minimal information
            return {
                'link_id': str(getattr(link, 'id', '')) if link else '',
                'ability_name': '',
                'technique_id': '',
                'executed_at': None,
                'timestamp': None,
                'command': '',
                'pid': None,
            }

    async def collect_operation_events(self, operation) -> list[dict]:
        events = []
        chain = getattr(operation, 'chain', [])
        for link in chain:
            events.append(self._event_from_link(link))
        return events

    # ------------------
    # Indexer Querying (Improved)
    # ------------------
    def _build_query(self, technique_id: str, center_ts: float) -> dict:
        """Improved query builder - wider time window and diverse field search (safe processing)"""
        try:
            # Time window setup (default: 7200s = 2 hours)
            window_sec = int(self.match.get('time_window_sec', self.config.get('time_window_sec', 7200)))

            # Convert Unix timestamp to UTC datetime (safely)
            try:
                center = datetime.fromtimestamp(center_ts, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                # Use current time if timestamp is invalid
                center = datetime.now(tz=timezone.utc)

            gte = (center - timedelta(seconds=window_sec)).isoformat()
            lte = (center + timedelta(seconds=window_sec)).isoformat()

            if self.debug:
                print(f"[DEBUG] Time window: {window_sec} seconds (±{window_sec/3600:.1f} hours)")
                print(f"[DEBUG] Center timestamp: {center_ts} → {center}")
                print(f"[DEBUG] Search range: {gte} to {lte}")
        except Exception as time_err:
            if self.debug:
                print(f"[DEBUG] Time window setup error: {time_err}")
            # fallback: search recent 2 hours
            gte = "now-2h"
            lte = "now+2h"

        # MITRE fields - add more variations
        mitre_fields = self.match.get('mitre_fields') or [
            'data.mitre.id',
            'rule.mitre.id', 
            'mitre.id',
            'rule.mitre.technique',
        ]
        
        message_fields = self.match.get('message_fields') or []

        # Configure 'should' conditions
        should = []
        
        # 1. Term query for each MITRE field (exact match)
        for f in mitre_fields:
            # Search with original field name
            should.append({'term': {f: technique_id}})
            
            # Try .keyword variation (for analyzed fields)
            if not f.endswith('.keyword'):
                should.append({'term': {f + '.keyword': technique_id}})
        
        # 2. Match phrase for message fields
        for f in message_fields:
            should.append({'match_phrase': {f: technique_id}})

        # 3. Search using Rule ID mapping (for alerts without MITRE fields)
        if technique_id in self.technique_to_rules:
            rule_ids = self.technique_to_rules[technique_id]
            for rule_id in rule_ids:
                should.append({'term': {'rule.id': rule_id}})
                should.append({'term': {'rule.id.keyword': rule_id}})
            if self.debug:
                print(f"[DEBUG] Added rule.id filters for {technique_id}: {rule_ids}")

        # 4. Add wildcard partial match (detect T1xxx format)
        should.append({'wildcard': {'data.mitre.id': f'*{technique_id}*'}})
        should.append({'wildcard': {'rule.mitre.id': f'*{technique_id}*'}})

        # Support both timestamp and @timestamp
        time_should = [
            {'range': {'@timestamp': {'gte': gte, 'lte': lte}}},
            {'range': {'timestamp': {'gte': gte, 'lte': lte}}}
        ]

        query = {
            'size': int(self.match.get('max_alerts', 200)),
            'query': {
                'bool': {
                    'filter': [
                        {
                            'bool': {
                                'should': time_should,
                                'minimum_should_match': 1
                            }
                        }
                    ],
                    'should': should,
                    'minimum_should_match': 1
                }
            },
            'sort': [
                {'@timestamp': {'order': 'asc', 'unmapped_type': 'date'}},
                {'timestamp': {'order': 'asc', 'unmapped_type': 'date'}}
            ]
        }
        
        # Print query in debug mode
        if self.debug:
            import json
            print(f"\n[DEBUG] Query for {technique_id} at {center}:")
            print(f"Time range: {gte} ~ {lte}")
            print(json.dumps(query, indent=2))
        
        return query

    def _extract_mitre_id(self, *values):
        """Extract MITRE ID - return first element if list"""
        for val in values:
            if val:
                if isinstance(val, list) and len(val) > 0:
                    # Return first element if list
                    return val[0] if val[0] else None
                elif isinstance(val, str):
                    # Return as is if string
                    return val
        return None

    def _summarize_hit(self, hit: dict) -> dict:
        """Summarize Elasticsearch/OpenSearch hit (safe processing)"""
        try:
            if not hit or not isinstance(hit, dict):
                return {}

            src = hit.get('_source', {}) or {}
            doc_id = hit.get('_id')

            # Handle rule
            rule = src.get('rule')
            if not isinstance(rule, dict):
                rule = {}

            # Handle data.mitre
            data = src.get('data')
            if isinstance(data, dict):
                data_mitre = data.get('mitre', {})
                if not isinstance(data_mitre, dict):
                    data_mitre = {}
            else:
                data_mitre = {}

            # Handle rule.mitre (can be list)
            raw_rule_mitre = rule.get('mitre')
            if isinstance(raw_rule_mitre, list) and raw_rule_mitre:
                rule_mitre = raw_rule_mitre[0] if isinstance(raw_rule_mitre[0], dict) else {}
            elif isinstance(raw_rule_mitre, dict):
                rule_mitre = raw_rule_mitre
            else:
                rule_mitre = {}

            # Handle agent
            agent = src.get('agent')
            if not isinstance(agent, dict):
                agent = {}

            # timestamp priority: @timestamp > timestamp
            ts = src.get('@timestamp') or src.get('timestamp')

            # Extract MITRE ID (safely)
            mitre_id = None
            try:
                mitre_id = self._extract_mitre_id(
                    data_mitre.get('id'),
                    rule_mitre.get('id'),
                    src.get('mitre.id'),
                    src.get('rule.mitre.id')
                )
            except Exception:
                mitre_id = None

            # Extract MITRE tactic
            mitre_tactic = (
                data_mitre.get('tactic') or
                rule_mitre.get('tactic') or
                src.get('mitre.tactic') or
                src.get('rule.mitre.tactic')
            )

            # Extract description
            description = (
                rule.get('description') or
                src.get('rule.description') or
                src.get('message') or
                src.get('full_log') or
                ''
            )

            return {
                'doc_id': doc_id,
                '@timestamp': ts,

                # Rule/Level
                'rule.id': rule.get('id') or src.get('rule.id'),
                'level': rule.get('level') or src.get('rule.level') or src.get('level'),

                # MITRE - try multiple paths
                'mitre.id': mitre_id,
                'mitre.tactic': mitre_tactic,

                # Agent info
                'agent.id': agent.get('id') or src.get('agent.id'),
                'agent.name': agent.get('name') or src.get('agent.name'),

                # Others
                'description': description,
                'data.audit.type': data.get('audit', {}).get('type') if isinstance(data, dict) and isinstance(data.get('audit'), dict) else None,
                'data.audit.exe': data.get('audit', {}).get('exe') if isinstance(data, dict) and isinstance(data.get('audit'), dict) else None,
            }
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] _summarize_hit failed: {e}")
            return {}

    def _search(self, technique_id: str, ts_epoch: float) -> list[dict]:
        """Perform search and print debug info (safe processing)"""
        # Validate inputs
        if not technique_id:
            if self.debug:
                print(f"[DEBUG] Skipping search - no technique_id")
            return []

        if not ts_epoch or not isinstance(ts_epoch, (int, float)):
            if self.debug:
                print(f"[DEBUG] Skipping search - invalid ts_epoch: {ts_epoch}")
            return []

        # Check client availability
        if not self.client:
            if self.debug:
                print(f"[DEBUG] No client available")
            return []

        index = self.wazuh.get('index_pattern') or self.config.get('index', 'wazuh-alerts-4.x-*')

        try:
            body = self._build_query(technique_id, ts_epoch)
        except Exception as query_err:
            if self.debug:
                print(f"[DEBUG] Query build failed: {query_err}")
            return []

        try:
            if self.debug:
                print(f"\n[DEBUG] Searching index: {index}")
                print(f"[DEBUG] Technique: {technique_id}")
                try:
                    print(f"[DEBUG] Timestamp: {datetime.fromtimestamp(ts_epoch, tz=timezone.utc)}")
                except Exception:
                    print(f"[DEBUG] Timestamp: {ts_epoch} (raw)")

            resp = self.client.search(index=index, body=body)

            if not resp:
                if self.debug:
                    print(f"[DEBUG] Empty response from search")
                return []

            hits = resp.get('hits', {}).get('hits', [])

            if self.debug:
                print(f"[DEBUG] Found {len(hits)} hits")
                if hits:
                    try:
                        print("[DEBUG] Sample hit:")
                        sample = hits[0].get('_source', {})
                        print(f"  - rule.id: {sample.get('rule', {}).get('id')}")
                        print(f"  - timestamp: {sample.get('@timestamp') or sample.get('timestamp')}")
                        print(f"  - data.mitre.id: {sample.get('data', {}).get('mitre', {}).get('id')}")
                        print(f"  - rule.mitre: {sample.get('rule', {}).get('mitre')}")
                        print(f"  - agent: {sample.get('agent')}")
                    except Exception:
                        pass

            # Process results (safely)
            results = []
            for h in hits:
                try:
                    summarized = self._summarize_hit(h)
                    if summarized:
                        results.append(summarized)
                        if self.debug and len(results) == 1:
                            print(f"[DEBUG] First summarized result:")
                            print(f"  - rule.id: {summarized.get('rule.id')}")
                            print(f"  - agent.id: {summarized.get('agent.id')}")
                            print(f"  - agent.name: {summarized.get('agent.name')}")
                except Exception as sum_err:
                    if self.debug:
                        print(f"[DEBUG] Failed to summarize hit: {sum_err}")
                    continue

            return results

        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Search failed: {e}")
            import traceback
            traceback.print_exc()
            return []

    async def correlate(self, operation) -> list[dict]:
        """Correlate Wazuh alerts for each link in the operation (safe processing)"""
        try:
            loop = asyncio.get_event_loop()
            results = []
            chain = getattr(operation, 'chain', [])

            if not chain:
                if self.debug:
                    print(f"[DEBUG] Operation {getattr(operation, 'name', 'Unknown')}: No chain links")
                return []

            if self.debug:
                print(f"\n[DEBUG] ========== Correlation Start ==========")
                print(f"[DEBUG] Operation: {getattr(operation, 'name', 'Unknown')}")
                print(f"[DEBUG] Total links: {len(chain)}")

            for idx, link in enumerate(chain, 1):
                try:
                    ability = getattr(link, 'ability', None)
                    technique_id = getattr(ability, 'technique_id', None) if ability else None
                    ability_name = getattr(ability, 'name', '') if ability else ''

                    ts_raw = getattr(link, 'finish', None) or getattr(link, 'start', None) or getattr(link, 'decide', None)
                    ts_dt = _to_dt(ts_raw)
                    ts_epoch = ts_dt.timestamp() if ts_dt else None

                    if self.debug:
                        print(f"\n[DEBUG] --- Link {idx}/{len(chain)} ---")
                        print(f"[DEBUG] Ability: {ability_name}")
                        print(f"[DEBUG] Technique: {technique_id}")
                        print(f"[DEBUG] Timestamp: {ts_dt} ({ts_epoch})")

                    matches = []
                    if technique_id and ts_epoch:
                        try:
                            matches = await loop.run_in_executor(None, self._search, technique_id, ts_epoch)

                            if self.debug:
                                if matches:
                                    print(f"[DEBUG] ✓ Matches found: {len(matches)}")
                                    for m in matches[:3]:  # 처음 3개만 샘플 출력
                                        print(f"  - rule.id={m.get('rule.id')}, ts={m.get('@timestamp')}")
                                else:
                                    print(f"[DEBUG] ✗ No matches found for technique={technique_id}")
                        except Exception as search_err:
                            if self.debug:
                                print(f"[DEBUG] ✗ Search error: {search_err}")
                            matches = []
                    else:
                        if self.debug:
                            reason = "no technique_id" if not technique_id else "no timestamp"
                            print(f"[DEBUG] ⊘ Skipped - {reason}")

                    results.append({
                        'link_id': str(getattr(link, 'id', '')),
                        'ability_name': ability_name or '',
                        'technique_id': technique_id or '',
                        'executed_at': _iso(ts_dt) if ts_dt else None,
                        'detected': len(matches) > 0,
                        'match_count': len(matches),
                        'matches': matches
                    })
                except Exception as link_err:
                    if self.debug:
                        print(f"[DEBUG] Error processing link {idx}: {link_err}")
                    # Add minimal info even on error
                    results.append({
                        'link_id': str(getattr(link, 'id', '')) if link else f'error_{idx}',
                        'ability_name': '',
                        'technique_id': '',
                        'executed_at': None,
                        'detected': False,
                        'match_count': 0,
                        'matches': []
                    })

            if self.debug:
                detected_count = sum(1 for r in results if r.get('detected', False))
                print(f"\n[DEBUG] ========== Correlation End ==========")
                print(f"[DEBUG] Total: {len(results)}, Detected: {detected_count}")

            return results
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Critical error in correlate: {e}")
            import traceback
            traceback.print_exc()
            return []