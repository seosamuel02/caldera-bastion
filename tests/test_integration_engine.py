"""
Unit tests for IntegrationEngine.

Tests cover the SIEM correlation engine functionality including:
- Configuration loading
- OpenSearch/Elasticsearch client building
- Query construction
- Alert matching and summarization
- Operation event correlation
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, mock_open
import yaml


class TestIntegrationEngineInitialization:
    """Tests for IntegrationEngine initialization."""

    def test_init_with_default_config(self, mock_opensearch_client, sample_rule_mitre_mapping):
        """Test engine initializes with default configuration."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine(rule_mitre_mapping=sample_rule_mitre_mapping)

                assert engine.client is not None
                assert engine.rule_mitre_mapping == sample_rule_mitre_mapping
                assert len(engine.technique_to_rules) > 0

    def test_init_with_overrides(self, mock_opensearch_client, sample_rule_mitre_mapping):
        """Test engine accepts configuration overrides."""
        overrides = {
            'debug': True,
            'wazuh': {
                'host': 'custom-host',
                'port': 9201
            }
        }

        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine(overrides=overrides, rule_mitre_mapping=sample_rule_mitre_mapping)

                assert engine.debug is True

    def test_technique_to_rules_reverse_mapping(self, mock_opensearch_client, sample_rule_mitre_mapping):
        """Test reverse mapping from technique to rule IDs is created."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine(rule_mitre_mapping=sample_rule_mitre_mapping)

                # T1078 should have multiple rule IDs
                assert 'T1078' in engine.technique_to_rules
                assert '5715' in engine.technique_to_rules['T1078']
                assert '5501' in engine.technique_to_rules['T1078']


class TestConfigurationLoading:
    """Tests for configuration file loading."""

    def test_load_settings_from_file(self, mock_opensearch_client):
        """Test configuration is loaded from YAML file."""
        config_content = """
debug: true
wazuh:
  host: test-host
  port: 9200
  scheme: https
match:
  time_window_sec: 3600
"""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                with patch('os.path.exists', return_value=True):
                    with patch('builtins.open', mock_open(read_data=config_content)):
                        from plugins.bastion.app.integration_engine import IntegrationEngine
                        engine = IntegrationEngine()

                        # Config should be loaded
                        assert engine.config is not None

    def test_load_settings_file_not_found(self, mock_opensearch_client):
        """Test graceful handling when config file doesn't exist."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                with patch('os.path.exists', return_value=False):
                    from plugins.bastion.app.integration_engine import IntegrationEngine
                    engine = IntegrationEngine()

                    # Should use empty config
                    assert engine.config is not None


class TestClientBuilding:
    """Tests for search client building."""

    def test_build_opensearch_client(self, mock_opensearch_client):
        """Test OpenSearch client is built when available."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()

                assert engine.client is not None

    def test_build_elasticsearch_client_fallback(self, mock_opensearch_client):
        """Test Elasticsearch client is used as fallback."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', None):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', return_value=mock_opensearch_client):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()

                assert engine.client is not None

    def test_no_client_available_raises_error(self):
        """Test error is raised when no client is available."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', None):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine

                with pytest.raises(RuntimeError) as exc_info:
                    IntegrationEngine()

                assert 'Neither opensearch-py nor elasticsearch' in str(exc_info.value)


class TestQueryBuilding:
    """Tests for OpenSearch query construction."""

    def test_build_query_with_technique_id(self, mock_opensearch_client, sample_rule_mitre_mapping):
        """Test query is built correctly for a technique ID."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine(rule_mitre_mapping=sample_rule_mitre_mapping)

                center_ts = datetime.now(timezone.utc).timestamp()
                query = engine._build_query('T1078', center_ts)

                assert 'query' in query
                assert 'bool' in query['query']
                assert 'should' in query['query']['bool']
                assert 'filter' in query['query']['bool']

    def test_build_query_includes_rule_id_mapping(self, mock_opensearch_client, sample_rule_mitre_mapping):
        """Test query includes rule ID filters for mapped techniques."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine(rule_mitre_mapping=sample_rule_mitre_mapping)

                center_ts = datetime.now(timezone.utc).timestamp()
                query = engine._build_query('T1078', center_ts)

                # Check that rule.id terms are in the should clause
                should_clauses = query['query']['bool']['should']
                rule_id_terms = [c for c in should_clauses if 'term' in c and 'rule.id' in c.get('term', {})]

                assert len(rule_id_terms) > 0

    def test_build_query_time_window(self, mock_opensearch_client):
        """Test query uses correct time window."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()
                engine.match = {'time_window_sec': 7200}  # 2 hours

                center_ts = datetime.now(timezone.utc).timestamp()
                query = engine._build_query('T1059', center_ts)

                # Query should have time range filter
                assert 'filter' in query['query']['bool']


class TestHitSummarization:
    """Tests for alert hit summarization."""

    def test_summarize_hit_basic(self, mock_opensearch_client):
        """Test basic hit summarization."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()

                hit = {
                    '_id': 'test_id_001',
                    '_source': {
                        '@timestamp': '2025-12-01T12:00:00Z',
                        'rule': {
                            'id': '5715',
                            'level': 8,
                            'description': 'SSH authentication success'
                        },
                        'agent': {
                            'id': '001',
                            'name': 'VM1-Ubuntu'
                        },
                        'data': {
                            'mitre': {
                                'id': 'T1078',
                                'tactic': 'Initial Access'
                            }
                        }
                    }
                }

                summary = engine._summarize_hit(hit)

                assert summary['doc_id'] == 'test_id_001'
                assert summary['@timestamp'] == '2025-12-01T12:00:00Z'
                assert summary['rule.id'] == '5715'
                assert summary['level'] == 8
                assert summary['mitre.id'] == 'T1078'
                assert summary['agent.id'] == '001'
                assert summary['agent.name'] == 'VM1-Ubuntu'

    def test_summarize_hit_with_array_mitre_id(self, mock_opensearch_client):
        """Test summarization handles array MITRE IDs."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()

                hit = {
                    '_id': 'test_id_002',
                    '_source': {
                        '@timestamp': '2025-12-01T12:00:00Z',
                        'rule': {
                            'id': '592',
                            'level': 5,
                            'mitre': [{'id': ['T1059', 'T1059.001'], 'tactic': ['Execution']}]
                        },
                        'agent': {'id': '001', 'name': 'VM1-Ubuntu'}
                    }
                }

                summary = engine._summarize_hit(hit)

                # Should extract first element from array
                assert summary['mitre.id'] is not None

    def test_summarize_hit_missing_fields(self, mock_opensearch_client):
        """Test summarization handles missing fields gracefully."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()

                hit = {
                    '_id': 'test_id_003',
                    '_source': {
                        '@timestamp': '2025-12-01T12:00:00Z'
                    }
                }

                summary = engine._summarize_hit(hit)

                assert summary['doc_id'] == 'test_id_003'
                assert summary['rule.id'] is None
                assert summary['agent.id'] is None


class TestSearchExecution:
    """Tests for search execution."""

    def test_search_returns_results(self, mock_opensearch_client, sample_rule_mitre_mapping):
        """Test search returns summarized results."""
        mock_opensearch_client.search = MagicMock(return_value={
            'hits': {
                'total': {'value': 1, 'relation': 'eq'},
                'hits': [
                    {
                        '_id': 'alert_001',
                        '_source': {
                            '@timestamp': '2025-12-01T12:00:00Z',
                            'rule': {'id': '5715', 'level': 8, 'description': 'Test'},
                            'agent': {'id': '001', 'name': 'VM1'},
                            'data': {'mitre': {'id': 'T1078'}}
                        }
                    }
                ]
            }
        })

        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine(rule_mitre_mapping=sample_rule_mitre_mapping)

                center_ts = datetime.now(timezone.utc).timestamp()
                results = engine._search('T1078', center_ts)

                assert len(results) == 1
                assert results[0]['mitre.id'] == 'T1078'

    def test_search_handles_empty_results(self, mock_opensearch_client):
        """Test search handles no results gracefully."""
        mock_opensearch_client.search = MagicMock(return_value={
            'hits': {'total': {'value': 0}, 'hits': []}
        })

        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()

                center_ts = datetime.now(timezone.utc).timestamp()
                results = engine._search('T1234', center_ts)

                assert results == []

    def test_search_handles_exception(self, mock_opensearch_client):
        """Test search handles exceptions gracefully."""
        mock_opensearch_client.search = MagicMock(side_effect=Exception("Connection failed"))

        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()

                center_ts = datetime.now(timezone.utc).timestamp()
                results = engine._search('T1078', center_ts)

                assert results == []

    def test_search_skips_invalid_input(self, mock_opensearch_client):
        """Test search skips when technique_id or timestamp is missing."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()

                # Missing technique_id
                results = engine._search(None, 123456789.0)
                assert results == []

                # Missing timestamp
                results = engine._search('T1078', None)
                assert results == []


class TestOperationCorrelation:
    """Tests for operation correlation."""

    @pytest.mark.asyncio
    async def test_correlate_operation(self, mock_opensearch_client, mock_caldera_operation):
        """Test correlation of a full operation."""
        mock_opensearch_client.search = MagicMock(return_value={
            'hits': {
                'total': {'value': 1, 'relation': 'eq'},
                'hits': [
                    {
                        '_id': 'alert_001',
                        '_source': {
                            '@timestamp': '2025-12-01T10:30:30Z',
                            'rule': {'id': '92604', 'level': 5, 'description': 'Process discovered'},
                            'agent': {'id': '001', 'name': 'VM1'},
                            'data': {'mitre': {'id': 'T1057'}}
                        }
                    }
                ]
            }
        })

        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()

                results = await engine.correlate(mock_caldera_operation)

                assert len(results) == 3  # 3 links in mock operation
                assert all('link_id' in r for r in results)
                assert all('detected' in r for r in results)
                assert all('matches' in r for r in results)

    @pytest.mark.asyncio
    async def test_correlate_empty_operation(self, mock_opensearch_client):
        """Test correlation of operation with no links."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()

                empty_operation = MagicMock()
                empty_operation.chain = []
                empty_operation.name = "Empty Operation"

                results = await engine.correlate(empty_operation)

                assert results == []

    @pytest.mark.asyncio
    async def test_collect_operation_events(self, mock_opensearch_client, mock_caldera_operation):
        """Test collection of operation events."""
        with patch('plugins.bastion.app.integration_engine.OpenSearch', return_value=mock_opensearch_client):
            with patch('plugins.bastion.app.integration_engine.Elasticsearch', None):
                from plugins.bastion.app.integration_engine import IntegrationEngine
                engine = IntegrationEngine()

                events = await engine.collect_operation_events(mock_caldera_operation)

                assert len(events) == 3
                assert all('link_id' in e for e in events)
                assert all('ability_name' in e for e in events)
                assert all('technique_id' in e for e in events)


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_to_dt_from_string(self):
        """Test datetime conversion from string."""
        from plugins.bastion.app.integration_engine import _to_dt

        result = _to_dt('2025-12-01T12:00:00Z')
        assert result is not None
        assert result.tzinfo is not None
        assert result.year == 2025
        assert result.month == 12
        assert result.day == 1

    def test_to_dt_from_timestamp(self):
        """Test datetime conversion from Unix timestamp."""
        from plugins.bastion.app.integration_engine import _to_dt

        ts = 1733054400.0  # 2025-12-01 12:00:00 UTC
        result = _to_dt(ts)
        assert result is not None
        assert result.tzinfo is not None

    def test_to_dt_from_datetime(self):
        """Test datetime conversion from datetime object."""
        from plugins.bastion.app.integration_engine import _to_dt

        dt = datetime(2025, 12, 1, 12, 0, 0)
        result = _to_dt(dt)
        assert result is not None
        assert result.tzinfo is not None

    def test_to_dt_from_none(self):
        """Test datetime conversion handles None."""
        from plugins.bastion.app.integration_engine import _to_dt

        result = _to_dt(None)
        assert result is None

    def test_iso_format(self):
        """Test ISO format conversion."""
        from plugins.bastion.app.integration_engine import _iso

        dt = datetime(2025, 12, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = _iso(dt)
        assert result == '2025-12-01T12:00:00Z'

    def test_iso_format_from_timestamp(self):
        """Test ISO format from Unix timestamp."""
        from plugins.bastion.app.integration_engine import _iso

        ts = 1733054400.0
        result = _iso(ts)
        assert result is not None
        assert 'T' in result

    def test_iso_format_none(self):
        """Test ISO format handles None."""
        from plugins.bastion.app.integration_engine import _iso

        result = _iso(None)
        assert result is None
