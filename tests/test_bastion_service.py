"""
Unit tests for BASTION service.

Tests cover the core BASTIONService class functionality including:
- Wazuh API authentication
- Alert retrieval and processing
- Agent correlation
- Operation correlation
- Dashboard data aggregation
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, AsyncMock, patch
from aiohttp import web
import json


class TestBASTIONServiceInitialization:
    """Tests for BASTIONService initialization."""

    def test_service_init_with_valid_config(self, mock_services, mock_wazuh_config):
        """Test service initializes correctly with valid configuration."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            assert service.manager_url == 'https://localhost:55000'
            assert service.indexer_url == 'https://localhost:9200'
            assert service.username == 'wazuh'
            assert service.verify_ssl is False
            assert service.token is None
            assert service.is_authenticated is False

    def test_service_init_with_default_config(self, mock_services):
        """Test service uses default values when config is empty."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, {})

            assert service.manager_url == 'https://localhost:55000'
            assert service.indexer_url == 'https://localhost:9200'
            assert service.username == 'wazuh'

    def test_rule_mitre_mapping_exists(self, mock_services, mock_wazuh_config):
        """Test that MITRE ATT&CK mapping is defined."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            assert hasattr(BASTIONService, 'RULE_MITRE_MAPPING')
            assert len(BASTIONService.RULE_MITRE_MAPPING) > 0
            assert '5715' in BASTIONService.RULE_MITRE_MAPPING
            assert BASTIONService.RULE_MITRE_MAPPING['5715'] == 'T1078'


class TestWazuhAuthentication:
    """Tests for Wazuh API authentication."""

    @pytest.mark.asyncio
    async def test_authenticate_success(self, mock_services, mock_wazuh_config, mock_wazuh_token):
        """Test successful authentication with Wazuh Manager."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value=mock_wazuh_token)

            with patch('aiohttp.ClientSession') as mock_session:
                mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response

                result = await service.authenticate()

                assert result is True
                assert service.token == mock_wazuh_token
                assert service.is_authenticated is True
                assert service.token_expiry is not None

    @pytest.mark.asyncio
    async def test_authenticate_failure(self, mock_services, mock_wazuh_config):
        """Test authentication failure handling."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            mock_response = AsyncMock()
            mock_response.status = 401
            mock_response.text = AsyncMock(return_value='Unauthorized')

            with patch('aiohttp.ClientSession') as mock_session:
                mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response

                with pytest.raises(Exception) as exc_info:
                    await service.authenticate()

                assert '401' in str(exc_info.value)
                assert service.is_authenticated is False

    @pytest.mark.asyncio
    async def test_ensure_authenticated_refreshes_expired_token(self, mock_services, mock_wazuh_config):
        """Test that expired tokens trigger re-authentication."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            # Set expired token
            service.token = "expired_token"
            service.token_expiry = datetime.utcnow() - timedelta(minutes=5)

            with patch.object(service, 'authenticate', new_callable=AsyncMock) as mock_auth:
                mock_auth.return_value = True
                await service._ensure_authenticated()
                mock_auth.assert_called_once()


class TestAlertRetrieval:
    """Tests for alert retrieval from Wazuh Indexer."""

    @pytest.mark.asyncio
    async def test_get_recent_alerts_success(
        self, mock_services, mock_wazuh_config, mock_web_request, mock_wazuh_alerts
    ):
        """Test successful alert retrieval."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            request = mock_web_request(query={'hours': '1', 'min_level': '7'})

            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_wazuh_alerts)

            with patch('aiohttp.ClientSession') as mock_session:
                mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response

                response = await service.get_recent_alerts(request)

                assert response.status == 200
                data = json.loads(response.text)
                assert data['success'] is True
                assert 'alerts' in data
                assert 'detected_techniques' in data

    @pytest.mark.asyncio
    async def test_get_recent_alerts_with_default_params(
        self, mock_services, mock_wazuh_config, mock_web_request, mock_wazuh_alerts
    ):
        """Test alert retrieval uses default parameters."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            request = mock_web_request(query={})

            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_wazuh_alerts)

            with patch('aiohttp.ClientSession') as mock_session:
                mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response

                response = await service.get_recent_alerts(request)

                assert response.status == 200


class TestHealthCheck:
    """Tests for health check endpoint."""

    @pytest.mark.asyncio
    async def test_health_check_authenticated(self, mock_services, mock_wazuh_config, mock_web_request):
        """Test health check when authenticated."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            service.is_authenticated = True
            service.token = "valid_token"

            request = mock_web_request()

            response = await service.health_check(request)

            assert response.status == 200
            data = json.loads(response.text)
            assert 'status' in data

    @pytest.mark.asyncio
    async def test_health_check_not_authenticated(self, mock_services, mock_wazuh_config, mock_web_request):
        """Test health check when not authenticated."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            service.is_authenticated = False
            service.token = None

            request = mock_web_request()

            response = await service.health_check(request)

            assert response.status == 200
            data = json.loads(response.text)
            assert data['status'] in ['warning', 'not_authenticated', 'ok']


class TestOperationCorrelation:
    """Tests for operation correlation functionality."""

    @pytest.mark.asyncio
    async def test_correlate_operation_success(
        self, mock_services, mock_wazuh_config, mock_web_request, mock_caldera_operation
    ):
        """Test successful operation correlation."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine') as mock_engine:
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            # Mock integration engine correlation
            mock_engine_instance = MagicMock()
            mock_engine_instance.correlate = AsyncMock(return_value=[
                {
                    'link_id': 'link-001',
                    'ability_name': 'Process Discovery',
                    'technique_id': 'T1057',
                    'detected': True,
                    'match_count': 2,
                    'matches': []
                }
            ])
            service.integration_engine = mock_engine_instance

            # Mock data_svc to return operation
            mock_services['data_svc'].locate = AsyncMock(return_value=[mock_caldera_operation])

            request = mock_web_request(json_data={'operation_id': 'op-12345678'})

            response = await service.correlate_operation(request)

            assert response.status == 200
            data = json.loads(response.text)
            assert 'operation_id' in data or 'correlation' in data or 'links' in data

    @pytest.mark.asyncio
    async def test_correlate_operation_not_found(
        self, mock_services, mock_wazuh_config, mock_web_request
    ):
        """Test correlation when operation not found."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            # Mock data_svc to return empty
            mock_services['data_svc'].locate = AsyncMock(return_value=[])

            request = mock_web_request(json_data={'operation_id': 'non-existent'})

            response = await service.correlate_operation(request)

            # Should handle gracefully
            assert response.status in [200, 404]


class TestAgentCorrelation:
    """Tests for agent correlation between Caldera and Wazuh."""

    @pytest.mark.asyncio
    async def test_get_agents_with_detections(
        self, mock_services, mock_wazuh_config, mock_web_request,
        mock_wazuh_agents, mock_caldera_agent
    ):
        """Test agent retrieval with detection correlation."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            service.is_authenticated = True
            service.token = "valid_token"

            # Mock data_svc to return Caldera agents
            mock_services['data_svc'].locate = AsyncMock(return_value=[mock_caldera_agent])

            request = mock_web_request(query={'hours': '1'})

            # Mock Wazuh Manager API response
            mock_manager_response = AsyncMock()
            mock_manager_response.status = 200
            mock_manager_response.json = AsyncMock(return_value=mock_wazuh_agents)

            # Mock Wazuh Indexer response
            mock_indexer_response = AsyncMock()
            mock_indexer_response.status = 200
            mock_indexer_response.json = AsyncMock(return_value={"hits": {"hits": []}})

            with patch('aiohttp.ClientSession') as mock_session:
                mock_session_instance = AsyncMock()
                mock_session_instance.get.return_value.__aenter__.return_value = mock_manager_response
                mock_session_instance.post.return_value.__aenter__.return_value = mock_indexer_response
                mock_session.return_value.__aenter__.return_value = mock_session_instance

                response = await service.get_agents_with_detections(request)

                assert response.status == 200
                data = json.loads(response.text)
                assert 'agents' in data


class TestDashboardSummary:
    """Tests for dashboard summary data."""

    @pytest.mark.asyncio
    async def test_get_dashboard_summary(
        self, mock_services, mock_wazuh_config, mock_web_request
    ):
        """Test dashboard summary retrieval."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            service.is_authenticated = True
            service.token = "valid_token"

            # Mock data_svc for operations and agents
            mock_services['data_svc'].locate = AsyncMock(return_value=[])

            request = mock_web_request(query={'hours': '1', 'min_level': '7'})

            # Mock Wazuh responses
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"hits": {"hits": []}})

            with patch('aiohttp.ClientSession') as mock_session:
                mock_session_instance = AsyncMock()
                mock_session_instance.get.return_value.__aenter__.return_value = mock_response
                mock_session_instance.post.return_value.__aenter__.return_value = mock_response
                mock_session.return_value.__aenter__.return_value = mock_session_instance

                response = await service.get_dashboard_summary(request)

                assert response.status == 200
                data = json.loads(response.text)
                # Verify KPI structure exists
                assert 'kpi' in data or 'success' in data


class TestTechniqueCoverage:
    """Tests for MITRE technique coverage analysis."""

    @pytest.mark.asyncio
    async def test_get_technique_coverage(
        self, mock_services, mock_wazuh_config, mock_web_request
    ):
        """Test technique coverage retrieval."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            service.is_authenticated = True
            service.token = "valid_token"

            # Mock data_svc for operations
            mock_services['data_svc'].locate = AsyncMock(return_value=[])

            request = mock_web_request(query={'hours': '24'})

            # Mock Wazuh responses
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"hits": {"hits": []}})

            with patch('aiohttp.ClientSession') as mock_session:
                mock_session_instance = AsyncMock()
                mock_session_instance.post.return_value.__aenter__.return_value = mock_response
                mock_session.return_value.__aenter__.return_value = mock_session_instance

                response = await service.get_technique_coverage(request)

                assert response.status == 200
                data = json.loads(response.text)
                assert 'techniques' in data or 'summary' in data or 'success' in data


class TestNotImplementedEndpoints:
    """Tests for stub endpoints."""

    @pytest.mark.asyncio
    async def test_generate_detection_report_stub(
        self, mock_services, mock_wazuh_config, mock_web_request
    ):
        """Test detection report endpoint returns not implemented."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            request = mock_web_request()

            response = await service.generate_detection_report(request)

            assert response.status == 200
            data = json.loads(response.text)
            assert 'message' in data or 'error' in data

    @pytest.mark.asyncio
    async def test_create_adaptive_operation_stub(
        self, mock_services, mock_wazuh_config, mock_web_request
    ):
        """Test adaptive operation endpoint returns not implemented."""
        with patch('plugins.bastion.app.bastion_service.IntegrationEngine'):
            from plugins.bastion.app.bastion_service import BASTIONService
            service = BASTIONService(mock_services, mock_wazuh_config)

            request = mock_web_request()

            response = await service.create_adaptive_operation(request)

            assert response.status == 200
            data = json.loads(response.text)
            assert 'message' in data or 'error' in data
