# BASTION - Caldera-Wazuh Integration Plugin

BASTION (Bridging Attack Simulations To Integrated Observability Network) is a Caldera plugin that integrates with Wazuh SIEM to automate attack simulation and detection validation.

## Features

- **Wazuh API Integration**: Connect to Wazuh Manager (55000) and Indexer (9200)
- **Real-time Alert Monitoring**: Query and display recent security alerts
- **Operation Correlation**: Automatically correlate Caldera operations with Wazuh detections
- **MITRE ATT&CK Coverage**: Analyze technique coverage with heat map visualization
- **Agent Matching**: Automatic Caldera agent to Wazuh agent mapping via facts
- **Detection Gap Analysis**: Identify undetected attack techniques
- **Vue 3 Dashboard**: Interactive dashboard with KPIs, charts, and filters

## Requirements

- Caldera 5.x
- Wazuh 4.x (Manager + Indexer)
- Python 3.9+

## Installation

### 1. Copy Plugin

```bash
# Navigate to Caldera directory
cd /path/to/caldera

# Copy or symlink the plugin
cp -r /path/to/bastion plugins/
# or
ln -s /path/to/bastion plugins/bastion
```

### 2. Install Dependencies

```bash
pip install -r plugins/bastion/requirements.txt
```

### 3. Configure Caldera

Add the plugin to `conf/local.yml`:

```yaml
plugins:
  - sandcat
  - stockpile
  - bastion

bastion:
  wazuh:
    manager_url: https://wazuh.manager:55000
    indexer_url: https://wazuh.indexer:9200
    manager_username: wazuh
    manager_password: your_password
    indexer_username: admin
    indexer_password: your_indexer_password
    verify_ssl: false
```

### 4. Start Caldera

```bash
python server.py --insecure
```

Access the dashboard at: `http://localhost:8888/plugins/bastion`

## API Endpoints

### Health Check
```bash
curl http://localhost:8888/plugin/bastion/health
```

### Get Recent Alerts
```bash
# Last 1 hour, level >= 7
curl "http://localhost:8888/plugin/bastion/alerts?hours=1&min_level=7"

# Last 24 hours, level >= 5
curl "http://localhost:8888/plugin/bastion/alerts?hours=24&min_level=5"
```

### Get Agents with Detections
```bash
curl "http://localhost:8888/plugin/bastion/agents?hours=1"
```

### Dashboard Summary
```bash
curl "http://localhost:8888/plugin/bastion/dashboard?hours=24&min_level=5"
```

### MITRE Technique Coverage
```bash
curl "http://localhost:8888/plugin/bastion/dashboard/techniques?hours=24"
```

### Correlate Operation
```bash
curl -X POST http://localhost:8888/plugin/bastion/correlate \
  -H "Content-Type: application/json" \
  -d '{"operation_id": "your-operation-id"}'
```

## Agent Matching

BASTION automatically matches Caldera agents to Wazuh agents using the following methods:

1. **Fact-based Matching** (Primary): Run the "Get Wazuh Agent ID" ability to extract the agent ID from `/var/ossec/etc/client.keys` and store it as a `wazuh.agent.id` fact.

2. **Hostname Fallback**: If no fact exists, BASTION attempts to match by hostname.

### Setup Agent Matching

1. Create an operation with the "Get Wazuh Agent ID" ability
2. Run the operation on target agents
3. The `wazuh.agent.id` fact will be automatically created
4. BASTION will use this fact for accurate agent correlation

## MITRE ATT&CK Mapping

BASTION includes a mapping between Wazuh rule IDs and MITRE ATT&CK techniques:

| Rule ID | Technique | Description |
|---------|-----------|-------------|
| 5715 | T1078 | SSH authentication success |
| 5501 | T1078 | PAM login session |
| 5402 | T1078.003 | Successful sudo to ROOT |
| 533 | T1049 | Network connections discovery |
| 592 | T1059 | Process creation |
| 92604 | T1057 | Process discovery |

## Dashboard Features

### Tier 1: Executive Overview
- Security Score (0-100)
- Detection Rate
- MTTD (Mean Time to Detection)
- Critical Gaps count

### Tier 2: Analyst Dashboard
- MITRE ATT&CK Heat Map
- Detection Timeline
- Agent Status Grid
- Operation Correlation Results

### Tier 3: Technical Details
- Raw alert data
- Detailed correlation logs
- Per-technique analysis

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-aiohttp coverage

# Run tests
cd plugins/bastion
pytest tests/ -v

# With coverage
coverage run -m pytest tests/ -v
coverage report
```

### Code Style

```bash
# Install pre-commit
pip install pre-commit
pre-commit install

# Run checks
pre-commit run --all-files
```

### Using tox

```bash
pip install tox
cd plugins/bastion
tox
```

## Troubleshooting

### Wazuh API Connection Failed
```
[BASTION] Wazuh Manager connection failed: Cannot connect to host
```
**Solution**: Verify Wazuh containers are running:
```bash
docker-compose ps
```

### SSL Certificate Error
```
ssl.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```
**Solution**: Set `verify_ssl: false` in configuration

### Plugin Loading Failed
```
[BASTION] Module import failed: No module named 'app.bastion_service'
```
**Solution**: Verify plugin directory structure:
```bash
ls -la plugins/bastion/app/
```

### Agent Matching Failed
If `wazuh.agent.id` fact is not created:
1. Check file permissions: `sudo chmod 644 /var/ossec/etc/client.keys`
2. Verify ability output in Caldera operation results

## Architecture

```
BASTION Plugin
├── hook.py                 # Plugin entry point, registers routes
├── app/
│   ├── bastion_service.py  # Core service (API handlers, correlation)
│   ├── integration_engine.py # OpenSearch query engine
│   └── parsers/
│       └── wazuh_agent_id.py # Fact parser for agent matching
├── data/
│   └── abilities/          # Caldera abilities for agent discovery
├── gui/
│   └── views/
│       └── bastion.vue     # Vue 3 dashboard component
└── conf/
    └── default.yml         # Default configuration
```

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Acknowledgments

- [MITRE Caldera](https://github.com/mitre/caldera) - Adversary emulation platform
- [Wazuh](https://wazuh.com/) - Open source security monitoring
- [MITRE ATT&CK](https://attack.mitre.org/) - Knowledge base of adversary tactics
