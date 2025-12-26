"""
BASTION (Bridging Attack Simulations To Integrated Observability Network)
Integrates Caldera with Wazuh SIEM to automate attack simulations and detection validation.
"""

from aiohttp import web
import logging

name = 'bastion'
description = 'BASTION - Bridging Attack Simulations To Integrated Observability Network'
address = None  # Vue handles routing (/plugins/bastion)

async def enable(services):
    """
    Initialize plugin.

    Args:
        services: Caldera core services dictionary
    """
    app_svc = services.get('app_svc')
    log = app_svc.log if app_svc else logging.getLogger('bastion')

    log.info('[BASTION] BASTION plugin initialization start')

    try:
        # Load configuration - prefer environment variables, then local.yml
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
            # Dedicated Elasticsearch connection for Discover (do not reuse Wazuh Manager credentials)
            'elastic_url': os.getenv('ELASTIC_URL') or 'http://elasticsearch:9200',
            'elastic_username': os.getenv('ELASTIC_USERNAME') or 'elastic',
            'elastic_password': os.getenv('ELASTIC_PASSWORD') or 'changeme',
            'verify_ssl': wazuh_config.get('verify_ssl', False),
            'alert_query_interval': bastion_config.get('refresh_interval', 300)
        }

        log.info(f'[BASTION] Wazuh Manager URL: {config["wazuh_manager_url"]}')

        # Initialize BASTION service
        from plugins.bastion.app.bastion_service import BASTIONService
        bastion_svc = BASTIONService(services, config)

        # Register REST API endpoints
        app = app_svc.application

        # Alerts endpoint
        app.router.add_route('GET', '/plugin/bastion/alerts',
                            bastion_svc.get_recent_alerts)

        # Correlation analysis endpoint
        app.router.add_route('POST', '/plugin/bastion/correlate',
                            bastion_svc.correlate_operation)

        # Detection report
        app.router.add_route('GET', '/plugin/bastion/detection_report',
                            bastion_svc.generate_detection_report)

        # Adaptive operation creation
        app.router.add_route('POST', '/plugin/bastion/adaptive_operation',
                            bastion_svc.create_adaptive_operation)

        # Health check endpoint
        app.router.add_route('GET', '/plugin/bastion/health',
                            bastion_svc.health_check)

        # Agent lookup endpoint
        app.router.add_route('GET', '/plugin/bastion/agents',
                            bastion_svc.get_agents_with_detections)

        # Dashboard summary endpoint
        app.router.add_route('GET', '/plugin/bastion/dashboard',
                            bastion_svc.get_dashboard_summary)

        # Tier 2: MITRE ATT&CK Technique coverage analysis
        app.router.add_route('GET', '/plugin/bastion/dashboard/techniques',
                            bastion_svc.get_technique_coverage)

        # Elasticsearch Discover proxy (indices/search)
        app.router.add_route('GET', '/plugin/bastion/es/indices',
                            bastion_svc.get_es_indices)
        app.router.add_route('POST', '/plugin/bastion/es/search',
                            bastion_svc.search_es)
        # Discover (MVP) dedicated API
        app.router.add_route('GET', '/api/discover/indices',
                            bastion_svc.get_discover_indices)
        app.router.add_route('POST', '/api/discover/search',
                            bastion_svc.discover_search)

        # Static file serving (CSS, JS, images) - currently unused
        # app.router.add_static('/bastion/static',
        #                      'plugins/bastion/static/',
        #                      append_version=True)

        log.info('[BASTION] REST API endpoint registration complete')
        log.info('[BASTION] Available endpoints:')
        log.info('  - GET  /plugin/bastion/alerts')
        log.info('  - POST /plugin/bastion/correlate')
        log.info('  - GET  /plugin/bastion/detection_report')
        log.info('  - POST /plugin/bastion/adaptive_operation')
        log.info('  - GET  /plugin/bastion/health')
        log.info('  - GET  /plugin/bastion/agents')
        log.info('  - GET  /plugin/bastion/dashboard')
        log.info('  - GET  /plugin/bastion/dashboard/techniques (NEW - Week 11)')
        log.info('  - GET  /plugin/bastion/es/indices (NEW - Discover)')
        log.info('  - POST /plugin/bastion/es/search  (NEW - Discover)')
        log.info('  - GET  /api/discover/indices (NEW - Discover MVP)')
        log.info('  - POST /api/discover/search  (NEW - Discover MVP)')
        log.info(f'  - GUI: http://localhost:8888{address}')

        # Start Wazuh authentication in background
        import asyncio

        async def authenticate_wazuh():
            try:
                await bastion_svc.authenticate()
                log.info('[BASTION] Wazuh API authentication succeeded')
            except Exception as auth_error:
                log.warning(f'[BASTION] Wazuh API authentication failed: {auth_error}')
                log.warning('[BASTION] Verify that the Wazuh server is running')

        asyncio.create_task(authenticate_wazuh())
        log.info('[BASTION] Wazuh authentication started in background')

        # Optional: start continuous monitoring
        if config.get('enable_continuous_monitoring', False):
            asyncio.create_task(bastion_svc.continuous_monitoring())
            log.info('[BASTION] Continuous monitoring started')

        log.info('[BASTION] Plugin enable complete ✓')

    except ImportError as e:
        log.error(f'[BASTION] Module import failed: {e}')
        log.error('[BASTION] Ensure plugins/bastion/app/bastion_service.py exists')
        raise
    except Exception as e:
        log.error(f'[BASTION] Plugin enable failed: {e}', exc_info=True)
        raise


async def expansion(services):
    """
    Optional plugin expansion hook.
    Called after all plugins are loaded.
    """
    log = services.get('app_svc').log
    log.debug('[BASTION] Expansion hook invoked')
