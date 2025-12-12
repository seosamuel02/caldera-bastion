"""
BASTION (Bridging Attack Simulations To Integrated Observability Network)
Integrates Caldera with Wazuh SIEM for automated attack simulation and detection validation.
"""

from aiohttp import web
import logging

name = 'bastion'
description = 'BASTION - Bridging Attack Simulations To Integrated Observability Network'
address = None  # Use Vue automatic routing (/plugins/bastion)

async def enable(services):
    """
    Plugin initialization function.

    Args:
        services: Caldera core services dictionary
    """
    app_svc = services.get('app_svc')
    log = app_svc.log if app_svc else logging.getLogger('bastion')

    log.info('[BASTION] Initializing BASTION Plugin')

    try:
        # Load configuration - environment variables take precedence, then local.yml
        import os

        bastion_config = app_svc.get_config().get('bastion', {}) if app_svc else {}
        wazuh_config = bastion_config.get('wazuh', {})

        config = {
            'wazuh_manager_url': os.getenv('WAZUH_MANAGER_URL') or wazuh_config.get('manager_url', 'https://wazuh.manager:55000'),
            'wazuh_indexer_url': os.getenv('WAZUH_INDEXER_URL') or wazuh_config.get('indexer_url', 'https://wazuh.indexer:9200'),
            'wazuh_username': os.getenv('WAZUH_USERNAME') or wazuh_config.get('manager_username', 'wazuh'),
            'wazuh_password': os.getenv('WAZUH_PASSWORD') or wazuh_config.get('manager_password', 'wazuh'),
            'indexer_username': os.getenv('WAZUH_INDEXER_USERNAME') or wazuh_config.get('indexer_username', 'admin'),
            'indexer_password': os.getenv('WAZUH_INDEXER_PASSWORD') or wazuh_config.get('indexer_password', 'SecretPassword'),
            'verify_ssl': wazuh_config.get('verify_ssl', False),
            'alert_query_interval': bastion_config.get('refresh_interval', 300)
        }

        log.info(f'[BASTION] Wazuh Manager URL: {config["wazuh_manager_url"]}')

        # Initialize BASTION service
        from plugins.bastion.app.bastion_service import BASTIONService
        bastion_svc = BASTIONService(services, config)

        # Register REST API endpoints
        app = app_svc.application

        # Alert retrieval endpoint
        app.router.add_route('GET', '/plugin/bastion/alerts',
                            bastion_svc.get_recent_alerts)

        # Correlation analysis endpoint
        app.router.add_route('POST', '/plugin/bastion/correlate',
                            bastion_svc.correlate_operation)

        # Detection report generation
        app.router.add_route('GET', '/plugin/bastion/detection_report',
                            bastion_svc.generate_detection_report)

        # Adaptive operation creation
        app.router.add_route('POST', '/plugin/bastion/adaptive_operation',
                            bastion_svc.create_adaptive_operation)

        # Health check endpoint
        app.router.add_route('GET', '/plugin/bastion/health',
                            bastion_svc.health_check)

        # Agent retrieval endpoint
        app.router.add_route('GET', '/plugin/bastion/agents',
                            bastion_svc.get_agents_with_detections)

        # Dashboard integrated data endpoint
        app.router.add_route('GET', '/plugin/bastion/dashboard',
                            bastion_svc.get_dashboard_summary)

        # Tier 2: MITRE ATT&CK Technique coverage analysis
        app.router.add_route('GET', '/plugin/bastion/dashboard/techniques',
                            bastion_svc.get_technique_coverage)

        log.info('[BASTION] REST API endpoints registered')
        log.info('[BASTION] Available endpoints:')
        log.info('  - GET  /plugin/bastion/alerts')
        log.info('  - POST /plugin/bastion/correlate')
        log.info('  - GET  /plugin/bastion/detection_report')
        log.info('  - POST /plugin/bastion/adaptive_operation')
        log.info('  - GET  /plugin/bastion/health')
        log.info('  - GET  /plugin/bastion/agents')
        log.info('  - GET  /plugin/bastion/dashboard')
        log.info('  - GET  /plugin/bastion/dashboard/techniques')
        log.info(f'  - GUI: http://localhost:8888{address}')

        # Start Wazuh authentication as background task
        import asyncio

        async def authenticate_wazuh():
            try:
                await bastion_svc.authenticate()
                log.info('[BASTION] Wazuh API authentication successful')
            except Exception as auth_error:
                log.warning(f'[BASTION] Wazuh API authentication failed: {auth_error}')
                log.warning('[BASTION] Please verify Wazuh server is running')

        asyncio.create_task(authenticate_wazuh())
        log.info('[BASTION] Starting Wazuh authentication in background')

        # Start background monitoring (optional)
        if config.get('enable_continuous_monitoring', False):
            asyncio.create_task(bastion_svc.continuous_monitoring())
            log.info('[BASTION] Continuous monitoring started')

        log.info('[BASTION] Plugin activation complete')

    except ImportError as e:
        log.error(f'[BASTION] Module import failed: {e}')
        log.error('[BASTION] Please verify plugins/bastion/app/bastion_service.py exists')
        raise
    except Exception as e:
        log.error(f'[BASTION] Plugin activation failed: {e}', exc_info=True)
        raise


async def expansion(services):
    """
    Plugin expansion function (optional).
    Called after all plugins are loaded.
    """
    log = services.get('app_svc').log
    log.debug('[BASTION] Expansion hook called')
