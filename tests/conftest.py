"""
Pytest configuration and fixtures for BASTION plugin tests.

This module provides shared fixtures for testing the BASTION plugin components
including mock Caldera services, Wazuh API responses, and test data.
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock, patch


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_app_svc():
    """Create mock Caldera app_svc."""
    app_svc = MagicMock()
    app_svc.log = MagicMock()
    app_svc.log.info = MagicMock()
    app_svc.log.error = MagicMock()
    app_svc.log.warning = MagicMock()
    app_svc.log.debug = MagicMock()
    app_svc.get_config = MagicMock(return_value={})
    app_svc.application = MagicMock()
    app_svc.application.router = MagicMock()
    app_svc.application.router.add_route = MagicMock()
    return app_svc


@pytest.fixture
def mock_data_svc():
    """Create mock Caldera data_svc."""
    data_svc = MagicMock()
    data_svc.locate = AsyncMock(return_value=[])
    data_svc.store = AsyncMock()
    return data_svc


@pytest.fixture
def mock_rest_svc():
    """Create mock Caldera rest_svc."""
    rest_svc = MagicMock()
    return rest_svc


@pytest.fixture
def mock_knowledge_svc():
    """Create mock Caldera knowledge_svc."""
    knowledge_svc = MagicMock()
    knowledge_svc.get_facts = AsyncMock(return_value=[])
    return knowledge_svc


@pytest.fixture
def mock_services(mock_app_svc, mock_data_svc, mock_rest_svc, mock_knowledge_svc):
    """Create mock Caldera services dictionary."""
    return {
        'app_svc': mock_app_svc,
        'data_svc': mock_data_svc,
        'rest_svc': mock_rest_svc,
        'knowledge_svc': mock_knowledge_svc,
    }


@pytest.fixture
def mock_wazuh_config():
    """Create mock Wazuh configuration."""
    return {
        'wazuh_manager_url': 'https://localhost:55000',
        'wazuh_indexer_url': 'https://localhost:9200',
        'wazuh_username': 'wazuh',
        'wazuh_password': 'test_password',
        'indexer_username': 'admin',
        'indexer_password': 'admin',
        'verify_ssl': False,
        'alert_query_interval': 300
    }


@pytest.fixture
def mock_wazuh_token():
    """Create mock Wazuh JWT token."""
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3YXp1aCJ9.mock_token"


@pytest.fixture
def mock_wazuh_agents():
    """Create mock Wazuh agents response."""
    return {
        "data": {
            "affected_items": [
                {
                    "id": "001",
                    "name": "VM1-Ubuntu",
                    "ip": "192.168.248.128",
                    "status": "active",
                    "os": {
                        "platform": "ubuntu",
                        "name": "Ubuntu",
                        "version": "22.04.5 LTS"
                    },
                    "lastKeepAlive": "2025-12-01T12:00:00Z"
                },
                {
                    "id": "002",
                    "name": "VM2-Windows",
                    "ip": "192.168.248.129",
                    "status": "active",
                    "os": {
                        "platform": "windows",
                        "name": "Microsoft Windows 11",
                        "version": "10.0.22000"
                    },
                    "lastKeepAlive": "2025-12-01T12:00:00Z"
                }
            ],
            "total_affected_items": 2,
            "total_failed_items": 0,
            "failed_items": []
        }
    }


@pytest.fixture
def mock_wazuh_alerts():
    """Create mock Wazuh alerts from Indexer."""
    return {
        "hits": {
            "total": {"value": 3, "relation": "eq"},
            "hits": [
                {
                    "_id": "alert_001",
                    "_source": {
                        "@timestamp": "2025-12-01T11:30:00Z",
                        "rule": {
                            "id": "5715",
                            "level": 8,
                            "description": "SSH authentication success"
                        },
                        "agent": {
                            "id": "001",
                            "name": "VM1-Ubuntu"
                        },
                        "data": {
                            "mitre": {
                                "id": "T1078",
                                "tactic": "Initial Access"
                            }
                        }
                    }
                },
                {
                    "_id": "alert_002",
                    "_source": {
                        "@timestamp": "2025-12-01T11:35:00Z",
                        "rule": {
                            "id": "592",
                            "level": 5,
                            "description": "Process creation detected"
                        },
                        "agent": {
                            "id": "001",
                            "name": "VM1-Ubuntu"
                        },
                        "data": {
                            "mitre": {
                                "id": "T1059",
                                "tactic": "Execution"
                            }
                        }
                    }
                },
                {
                    "_id": "alert_003",
                    "_source": {
                        "@timestamp": "2025-12-01T11:40:00Z",
                        "rule": {
                            "id": "533",
                            "level": 7,
                            "description": "Network connections discovered"
                        },
                        "agent": {
                            "id": "001",
                            "name": "VM1-Ubuntu"
                        },
                        "data": {
                            "mitre": {
                                "id": "T1049",
                                "tactic": "Discovery"
                            }
                        }
                    }
                }
            ]
        }
    }


@pytest.fixture
def mock_caldera_agent():
    """Create mock Caldera agent object."""
    agent = MagicMock()
    agent.paw = "abc123"
    agent.host = "VM1-Ubuntu"
    agent.platform = "linux"
    agent.executors = ["sh", "bash"]
    agent.last_seen = datetime.now(timezone.utc)
    agent.trusted = True
    agent.pending_contact = None
    return agent


@pytest.fixture
def mock_caldera_operation():
    """Create mock Caldera operation object."""
    operation = MagicMock()
    operation.id = "op-12345678"
    operation.name = "Test Operation"
    operation.start = datetime(2025, 12, 1, 10, 0, 0, tzinfo=timezone.utc)
    operation.finish = datetime(2025, 12, 1, 12, 0, 0, tzinfo=timezone.utc)
    operation.state = "finished"

    # Create mock links (attack steps)
    link1 = MagicMock()
    link1.id = "link-001"
    link1.ability = MagicMock()
    link1.ability.name = "Process Discovery"
    link1.ability.technique_id = "T1057"
    link1.finish = datetime(2025, 12, 1, 10, 30, 0, tzinfo=timezone.utc)
    link1.start = datetime(2025, 12, 1, 10, 29, 0, tzinfo=timezone.utc)
    link1.status = 0  # success
    link1.pid = 1234
    link1.command = b"ps aux"

    link2 = MagicMock()
    link2.id = "link-002"
    link2.ability = MagicMock()
    link2.ability.name = "System Information Discovery"
    link2.ability.technique_id = "T1082"
    link2.finish = datetime(2025, 12, 1, 10, 35, 0, tzinfo=timezone.utc)
    link2.start = datetime(2025, 12, 1, 10, 34, 0, tzinfo=timezone.utc)
    link2.status = 0
    link2.pid = 1235
    link2.command = b"uname -a"

    link3 = MagicMock()
    link3.id = "link-003"
    link3.ability = MagicMock()
    link3.ability.name = "Command Execution"
    link3.ability.technique_id = "T1059"
    link3.finish = datetime(2025, 12, 1, 10, 40, 0, tzinfo=timezone.utc)
    link3.start = datetime(2025, 12, 1, 10, 39, 0, tzinfo=timezone.utc)
    link3.status = 0
    link3.pid = 1236
    link3.command = b"whoami"

    operation.chain = [link1, link2, link3]

    return operation


@pytest.fixture
def mock_aiohttp_response():
    """Create mock aiohttp response."""
    def _create_response(status=200, json_data=None, text_data=None):
        response = AsyncMock()
        response.status = status
        if json_data is not None:
            response.json = AsyncMock(return_value=json_data)
        if text_data is not None:
            response.text = AsyncMock(return_value=text_data)
        return response
    return _create_response


@pytest.fixture
def mock_web_request():
    """Create mock aiohttp web request."""
    def _create_request(query=None, json_data=None, match_info=None):
        request = MagicMock()
        request.query = query or {}
        request.json = AsyncMock(return_value=json_data or {})
        request.match_info = match_info or {}
        return request
    return _create_request


@pytest.fixture
def sample_rule_mitre_mapping():
    """Create sample rule to MITRE mapping."""
    return {
        '5715': 'T1078',
        '5501': 'T1078',
        '5402': 'T1078.003',
        '533': 'T1049',
        '510': 'T1082',
        '550': 'T1083',
        '592': 'T1059',
        '92604': 'T1057',
    }


@pytest.fixture
def mock_opensearch_client():
    """Create mock OpenSearch client."""
    client = MagicMock()
    client.search = MagicMock(return_value={
        "hits": {
            "total": {"value": 0, "relation": "eq"},
            "hits": []
        }
    })
    client.info = MagicMock(return_value={"version": {"number": "2.11.0"}})
    return client
