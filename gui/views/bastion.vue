<script setup>
import { ref, reactive, onMounted, onUnmounted, inject, computed, watch } from "vue";
import DiscoverPanel from "../components/Discover/DiscoverPanel.vue";
import { Bar, Line } from 'vue-chartjs';
import {
  Chart as ChartJS,
  Title,
  Tooltip,
  Legend,
  BarElement,
  LineElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Filler
} from 'chart.js';

ChartJS.register(
  Title,
  Tooltip,
  Legend,
  BarElement,
  LineElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Filler
);

const detectionEvents = ref([]);
const expandedDetections = ref(new Set());

// Pagination for detection events
const detectionCurrentPage = ref(1);
const detectionPageSize = ref(10);
const allDetectionEvents = ref([]); // For storing all events from last 72 hours

const toggleDetectionDetail = (idx) => {
  if (expandedDetections.value.has(idx)) {
    expandedDetections.value.delete(idx);
  } else {
    expandedDetections.value.add(idx);
  }
  expandedDetections.value = new Set(expandedDetections.value);
};

const isDetectionExpanded = (idx) => {
  return expandedDetections.value.has(idx);
};

const transformDetectionEvents = (rawEvents) => {
  console.log("[DEBUG] rawEvents:", rawEvents);
  detectionEvents.value = (rawEvents || []).map(ev => ({
    timestamp: ev['@timestamp'] || ev.timestamp || null,
    agent_name: ev['agent.name'] || ev.agent_name || null,
    agent_id: ev['agent.id'] || ev.agent_id || null,
    agent_os: ev.agent_os || null,
    rule_id: ev['rule.id'] || ev.rule_id || null,
    rule_level: ev.level ?? ev.rule_level ?? null,
    technique_id: ev.technique_id || ev['mitre.id'] || null,
    tactic: ev.tactic || null,
    description: ev.description || ev.message || '',
    match_status: (ev.match_status || 'UNMATCHED').toLowerCase(),
    attack_step_id: ev.attack_step_id || ev.link_id || null,
    match_source: ev.match_source || ev.source || 'wazuh',
    opId: ev.opId || ev.operation_id || ev.op_id || null,
    // Raw event data for Splunk-like detail view
    full_log: ev.full_log || '',
    raw_data: ev.raw_data || {},
    syscheck: ev.syscheck || {},
    location: ev.location || '',
    predecoder: ev.predecoder || {},
    decoder: ev.decoder || {},
    // SUMMARY fields (API response: agent_ip, audit_command, audit_cwd, audit_type, audit_exe, srcip, dstip)
    agent_ip: ev.agent_ip || ev['agent.ip'] || null,
    audit_command: ev.audit_command || ev['data.audit.command'] || null,
    audit_cwd: ev.audit_cwd || ev['data.audit.cwd'] || null,
    audit_type: ev.audit_type || ev['data.audit.type'] || null,
    audit_exe: ev.audit_exe || ev['data.audit.exe'] || null,
    srcip: ev.srcip || ev['data.srcip'] || ev.src_ip || null,
    dstip: ev.dstip || ev['data.dstip'] || ev.dst_ip || null,
  }));
  console.log("[DEBUG] mappedEvents:", detectionEvents.value);
};

const $api = inject("$api");

const isLoading = ref(false);
const showSubText = ref(false);
const selectedAgentHost = ref(null);

const dashboardData = reactive({
  kpi: {
    total_operations: 0,
    total_agents: 0,
    total_attack_steps: 0,
    total_detections: 0,
    coverage: 0,
    last_seen: null
  },
  operations: [],
  detection_events: [],
  query_time: null
});

const filters = reactive({
  hours: 72,
  min_level: 5,
  operation_id: 'all',
  os_filter: 'all',
  env_filter: 'all',
  search: ''
});

const allOperations = ref([]);

const agentQueryHours = ref(24);
const agentsData = reactive({
  total_agents: 0,
  agents: [],
  query_time: null
});

const correlationOperationId = ref('');
const correlationResult = ref(null);
const isCorrelating = ref(false);

const heatMapData = reactive({
  techniques: [],
  tactics: [],
  summary: {
    total_techniques: 0,
    total_simulated: 0,
    total_detected: 0,
    overall_detection_rate: 0
  }
});

watch(() => filters.operation_id, async (newValue, oldValue) => {
  if (newValue !== oldValue) {
    detectionCurrentPage.value = 1; // Reset page
    if (newValue === 'all') {
      await fetchAllDetectionEvents(); // Load all logs from last 72 hours when 'all' selected
    }
    await fetchDashboardSummary();
    await fetchAgents();
    await fetchHeatMapData();
  }
});

watch(() => filters.os_filter, async (newValue, oldValue) => {
  if (newValue !== oldValue) {
    await fetchDashboardSummary();
    await fetchAgents();
    await fetchHeatMapData();
  }
});

watch(() => filters.search, async (newValue, oldValue) => {
  if (newValue !== oldValue) {
    await fetchDashboardSummary();
    await fetchAgents();
    await fetchHeatMapData();
  }
});

let refreshInterval;

onMounted(async () => {
  await fetchAgents();
  await fetchDashboardSummary();
  await fetchHeatMapData();

  // Load all events from last 72 hours if operation_id is 'all'
  if (filters.operation_id === 'all') {
    await fetchAllDetectionEvents();
  }

  refreshInterval = setInterval(async () => {
    await fetchAgents();
    await fetchDashboardSummary();
    await fetchHeatMapData();
  }, 30000);
});

onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval);
  }
});

const fetchDashboardSummary = async () => {
  try {
    let url = `/plugin/bastion/dashboard?hours=${filters.hours}&min_level=${filters.min_level}`;
    if (filters.operation_id && filters.operation_id !== 'all') {
      url += `&operation_id=${filters.operation_id}`;
    }
    if (filters.os_filter && filters.os_filter !== 'all') {
      url += `&os_filter=${filters.os_filter}`;
    }
    if (filters.search) {
      url += `&search=${encodeURIComponent(filters.search)}`;
    }
    const response = await $api.get(url);
    Object.assign(dashboardData, response.data);
    transformDetectionEvents(response.data.detection_events || []);
    if (filters.operation_id === 'all' && response.data.operations) {
      allOperations.value = response.data.operations;
    }
  } catch (error) {
    console.error('Failed to fetch dashboard summary:', error);
  }
};

const fetchAgents = async () => {
  try {
    let url = `/plugin/bastion/agents?hours=${agentQueryHours.value}`;
    if (filters.operation_id && filters.operation_id !== 'all') {
      url += `&operation_id=${filters.operation_id}`;
    }
    if (filters.os_filter && filters.os_filter !== 'all') {
      url += `&os_filter=${filters.os_filter}`;
    }
    if (filters.search) {
      url += `&search=${encodeURIComponent(filters.search)}`;
    }
    const response = await $api.get(url);
    Object.assign(agentsData, response.data);
  } catch (error) {
    console.error('Failed to fetch agents:', error);
  }
};

const fetchHeatMapData = async () => {
  try {
    let url = `/plugin/bastion/dashboard/techniques?hours=${filters.hours}`;
    if (filters.operation_id && filters.operation_id !== 'all') {
      url += `&operation_id=${filters.operation_id}`;
    }
    if (filters.os_filter && filters.os_filter !== 'all') {
      url += `&os_filter=${filters.os_filter}`;
    }
    if (filters.search) {
      url += `&search=${encodeURIComponent(filters.search)}`;
    }
    const response = await $api.get(url);
    Object.assign(heatMapData, response.data);
  } catch (error) {
    console.error('Failed to fetch heat map data:', error);
  }
};

// Load all detection events from last 72 hours when operation_id is 'all'
const fetchAllDetectionEvents = async () => {
  try {
    const url = `/plugin/bastion/dashboard?hours=72&min_level=${filters.min_level}`;
    const response = await $api.get(url);
    const rawEvents = response.data.detection_events || [];
    allDetectionEvents.value = rawEvents.map(ev => ({
      timestamp: ev['@timestamp'] || ev.timestamp || null,
      agent_name: ev['agent.name'] || ev.agent_name || null,
      agent_id: ev['agent.id'] || ev.agent_id || null,
      agent_os: ev.agent_os || null,
      rule_id: ev['rule.id'] || ev.rule_id || null,
      rule_level: ev.level ?? ev.rule_level ?? null,
      technique_id: ev.technique_id || ev['mitre.id'] || null,
      tactic: ev.tactic || null,
      description: ev.description || ev.message || '',
      match_status: (ev.match_status || 'UNMATCHED').toLowerCase(),
      attack_step_id: ev.attack_step_id || ev.link_id || null,
      match_source: ev.match_source || ev.source || 'wazuh',
      opId: ev.opId || ev.operation_id || ev.op_id || null,
      full_log: ev.full_log || '',
      raw_data: ev.raw_data || {},
      syscheck: ev.syscheck || {},
      location: ev.location || '',
      predecoder: ev.predecoder || {},
      decoder: ev.decoder || {},
    }));
    console.log("[DEBUG] Loaded all detection events for 72h:", allDetectionEvents.value.length);
  } catch (error) {
    console.error('Failed to fetch all detection events:', error);
    allDetectionEvents.value = [];
  }
};

const refreshData = async () => {
  isLoading.value = true;
  try {
    await Promise.all([fetchAgents(), fetchDashboardSummary(), fetchHeatMapData()]);
    window.toast && window.toast('Data refreshed successfully', true);
  } catch (error) {
    window.toast && window.toast('Failed to refresh data', false);
  } finally {
    isLoading.value = false;
  }
};

const correlateOperation = async () => {
  if (!correlationOperationId.value) return;
  isCorrelating.value = true;
  try {
    const response = await $api.post('/plugin/bastion/correlate', {
      operation_id: correlationOperationId.value
    });
    correlationResult.value = response.data;
    window.toast && window.toast('Correlation analysis complete', true);
  } catch (error) {
    window.toast && window.toast('Correlation analysis failed', false);
    console.error('Correlation failed:', error);
  } finally {
    isCorrelating.value = false;
  }
};

const selectAgent = (agentHost) => {
  if (selectedAgentHost.value === agentHost) {
    selectedAgentHost.value = null;
  } else {
    selectedAgentHost.value = agentHost;
  }
};

const clearAgentFilter = () => {
  selectedAgentHost.value = null;
};

const filteredDetections = computed(() => {
  // Use allDetectionEvents if operation_id is 'all', otherwise use existing detectionEvents
  let detections = filters.operation_id === 'all'
    ? allDetectionEvents.value
    : detectionEvents.value;

  if (selectedAgentHost.value) {
    detections = detections.filter(d => d.agent_name === selectedAgentHost.value);
  }
  if (filters.os_filter !== 'all') {
    detections = detections.filter(d => {
      if (!d.agent_os) return false;
      const platform = d.agent_os.toLowerCase();
      const filter = filters.os_filter.toLowerCase();
      return platform === filter || platform.includes(filter);
    });
  }
  if (filters.search) {
    const search = filters.search.toLowerCase();
    detections = detections.filter(d =>
      d.description?.toLowerCase().includes(search) ||
      d.agent_name?.toLowerCase().includes(search) ||
      d.technique_id?.toLowerCase().includes(search)
    );
  }
  return detections;
});

// Pagination related computed
const detectionTotalPages = computed(() => {
  return Math.ceil(filteredDetections.value.length / detectionPageSize.value) || 1;
});

const paginatedDetections = computed(() => {
  const start = (detectionCurrentPage.value - 1) * detectionPageSize.value;
  const end = start + detectionPageSize.value;
  return filteredDetections.value.slice(start, end);
});

const detectionPageNumbers = computed(() => {
  const total = detectionTotalPages.value;
  const current = detectionCurrentPage.value;
  const pages = [];

  if (total <= 7) {
    for (let i = 1; i <= total; i++) pages.push(i);
  } else {
    pages.push(1);
    if (current > 3) pages.push('...');

    let start = Math.max(2, current - 1);
    let end = Math.min(total - 1, current + 1);

    if (current <= 3) {
      end = 4;
    }
    if (current >= total - 2) {
      start = total - 3;
    }

    for (let i = start; i <= end; i++) {
      if (i > 1 && i < total) pages.push(i);
    }

    if (current < total - 2) pages.push('...');
    pages.push(total);
  }
  return pages;
});

const goToDetectionPage = (page) => {
  if (page === '...') return;
  detectionCurrentPage.value = page;
  expandedDetections.value = new Set(); // Reset expanded items on page change
};

const prevDetectionPage = () => {
  if (detectionCurrentPage.value > 1) {
    detectionCurrentPage.value--;
    expandedDetections.value = new Set();
  }
};

const nextDetectionPage = () => {
  if (detectionCurrentPage.value < detectionTotalPages.value) {
    detectionCurrentPage.value++;
    expandedDetections.value = new Set();
  }
};

const sortedAgents = computed(() => {
  let agents = [...agentsData.agents];
  if (filters.os_filter !== 'all') {
    agents = agents.filter(agent => {
      const platform = agent.platform.toLowerCase();
      const filter = filters.os_filter.toLowerCase();
      return platform === filter || platform.includes(filter);
    });
  }
  return agents.sort((a, b) => {
    if (a.alive !== b.alive) {
      return b.alive ? 1 : -1;
    }
    return a.host.localeCompare(b.host);
  });
});

const filteredOperations = computed(() => {
  if (filters.operation_id === 'all') {
    return dashboardData.operations;
  }
  return dashboardData.operations.filter(op => op.id === filters.operation_id);
});

const securityScoreColor = computed(() => {
  const score = filteredKPI.value.security_score || 0;
  if (score >= 90) return 'cyber-green';
  if (score >= 80) return 'cyber-green';
  if (score >= 70) return 'cyber-yellow';
  if (score >= 60) return 'cyber-orange';
  return 'cyber-red';
});

const heatMapSummaryColor = computed(() => {
  const rate = Math.min(heatMapData.summary.overall_detection_rate || 0, 100);
  if (rate >= 80) return '#00ff88';
  if (rate >= 60) return '#ffcc00';
  if (rate > 0) return '#ff9500';
  return '#ff3366';
});

const formatTimestamp = (timestamp) => {
  if (!timestamp) return 'N/A';
  const date = new Date(timestamp);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
};

const getLevelClass = (level) => {
  if (level >= 12) return 'critical';
  if (level >= 10) return 'high';
  if (level >= 7) return 'medium';
  return 'low';
};

const formatCoverage = (coverage) => {
  return `${(coverage * 100).toFixed(1)}%`;
};

// Flatten nested object for Splunk-like display
const flattenEventData = (obj, prefix = '') => {
  const result = {};
  if (!obj || typeof obj !== 'object') return result;

  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;

    // Skip mitre field (already displayed separately)
    if (key === 'mitre') continue;

    if (value && typeof value === 'object' && !Array.isArray(value)) {
      // Recursively flatten nested objects
      Object.assign(result, flattenEventData(value, fullKey));
    } else {
      result[fullKey] = value;
    }
  }
  return result;
};

// Format event value for display
const formatEventValue = (value) => {
  if (value === null || value === undefined) return 'N/A';
  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(', ') : '[]';
  }
  if (typeof value === 'object') {
    return JSON.stringify(value);
  }
  return String(value);
};

const filteredKPI = computed(() => {
  const filtered_agents = sortedAgents.value;
  const filtered_detections = filteredDetections.value;
  const filtered_operations = filteredOperations.value;

  // Calculate total attack steps from filtered operations
  let total_attack_steps = 0;
  const uniqueTechniques = new Set();
  const detectedTechniques = new Set();
  const uniqueTactics = new Set();

  for (const op of filtered_operations) {
    for (const step of (op.attack_steps || [])) {
      // Apply OS filter to attack steps
      if (filters.os_filter !== 'all') {
        const agentPlatform = op.agent_platforms?.[step.paw];
        if (!agentPlatform) continue;
        const platform = agentPlatform.toLowerCase();
        const filterOs = filters.os_filter.toLowerCase();
        if (platform !== filterOs && !platform.includes(filterOs)) {
          continue;
        }
      }
      total_attack_steps += 1;
      if (step.technique_id) {
        uniqueTechniques.add(step.technique_id);
      }
      if (step.tactic) {
        uniqueTactics.add(step.tactic);
      }
    }
  }

  // Calculate detected techniques from filtered detections
  for (const detection of filtered_detections) {
    if (detection.technique_id) {
      detectedTechniques.add(detection.technique_id);
    }
  }

  // Calculate detection rate based on filtered data
  const detection_rate = total_attack_steps > 0
    ? Math.min(100, Math.round((filtered_detections.length / total_attack_steps) * 100))
    : 0;

  // Calculate security score from detection rate
  const security_score = detection_rate;

  // Calculate security grade from score
  let security_grade = 'N/A';
  if (total_attack_steps > 0) {
    if (security_score >= 90) security_grade = 'A';
    else if (security_score >= 80) security_grade = 'B';
    else if (security_score >= 70) security_grade = 'C';
    else if (security_score >= 60) security_grade = 'D';
    else security_grade = 'F';
  }

  // Calculate critical gaps (techniques simulated but not detected)
  const critical_gaps = uniqueTechniques.size - detectedTechniques.size;

  // Calculate tactic coverage
  const tactic_coverage = uniqueTactics.size;

  // Calculate MTTD from matched detections
  let mttd_minutes = 0;
  const matchedDetections = filtered_detections.filter(d => d.match_status === 'matched');
  if (matchedDetections.length > 0) {
    // Use backend MTTD if available, otherwise show 0
    const kpi = dashboardData.kpi || {};
    mttd_minutes = kpi.mttd_minutes || 0;
  }

  const coverage = total_attack_steps > 0
    ? filtered_detections.length / total_attack_steps
    : 0;

  const last_seen = filtered_agents.length > 0
    ? filtered_agents.reduce((latest, agent) => {
      const agentTime = new Date(agent.last_seen);
      return agentTime > latest ? agentTime : latest;
    }, new Date(0)).toISOString()
    : null;

  return {
    total_operations: filtered_operations.length,
    total_agents: filtered_agents.length,
    total_attack_steps: total_attack_steps,
    total_detections: filtered_detections.length,
    coverage: coverage,
    last_seen: last_seen,
    security_score: security_score,
    security_grade: security_grade,
    detection_rate: detection_rate,
    mttd_minutes: mttd_minutes,
    critical_gaps: Math.max(0, critical_gaps),
    tactic_coverage: tactic_coverage
  };
});

const tacticChartData = computed(() => {
  const tacticStats = {};
  for (const op of filteredOperations.value) {
    for (const step of (op.attack_steps || [])) {
      if (filters.os_filter !== 'all') {
        const agentPlatform = op.agent_platforms?.[step.paw];
        if (!agentPlatform) continue;
        const platform = agentPlatform.toLowerCase();
        const filterOs = filters.os_filter.toLowerCase();
        if (platform !== filterOs && !platform.includes(filterOs)) {
          continue;
        }
      }
      const tactic = step.tactic;
      if (tactic) {
        if (!tacticStats[tactic]) {
          tacticStats[tactic] = { executed: 0, detected: 0 };
        }
        tacticStats[tactic].executed += 1;
      }
    }
  }
  for (const detection of filteredDetections.value) {
    const tactic = detection.tactic;
    if (tactic) {
      if (!tacticStats[tactic]) {
        tacticStats[tactic] = { executed: 0, detected: 0 };
      }
      tacticStats[tactic].detected += 1;
    }
  }
  // Cap detected count at executed count per tactic to prevent chart distortion
  for (const tactic of Object.keys(tacticStats)) {
    if (tacticStats[tactic].detected > tacticStats[tactic].executed) {
      tacticStats[tactic].detected = tacticStats[tactic].executed;
    }
  }
  const tactics = Object.keys(tacticStats).sort();
  if (tactics.length === 0) {
    return { labels: [], datasets: [] };
  }
  const detectedColors = tactics.map(tactic => {
    const stats = tacticStats[tactic];
    const detectionRate = stats.executed > 0 ? (stats.detected / stats.executed) * 100 : 0;
    if (detectionRate === 0) {
      return 'rgba(255, 51, 102, 0.8)';
    } else if (detectionRate < 80) {
      return 'rgba(255, 204, 0, 0.8)';
    } else {
      return 'rgba(0, 255, 136, 0.8)';
    }
  });
  const detectedBorderColors = tactics.map(tactic => {
    const stats = tacticStats[tactic];
    const detectionRate = stats.executed > 0 ? (stats.detected / stats.executed) * 100 : 0;
    if (detectionRate === 0) {
      return '#ff3366';
    } else if (detectionRate < 80) {
      return '#ffcc00';
    } else {
      return '#00ff88';
    }
  });
  return {
    labels: tactics,
    datasets: [
      {
        label: 'EXECUTED',
        backgroundColor: 'rgba(0, 212, 255, 0.6)',
        borderColor: '#00d4ff',
        borderWidth: 2,
        data: tactics.map(t => tacticStats[t].executed)
      },
      {
        label: 'DETECTED',
        backgroundColor: detectedColors,
        borderColor: detectedBorderColors,
        borderWidth: 2,
        data: tactics.map(t => tacticStats[t].detected)
      }
    ]
  };
});

const tacticChartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      display: true,
      position: 'top',
      labels: {
        color: '#00ff88',
        font: { family: "'JetBrains Mono', monospace", size: 10, weight: 'bold' },
        boxWidth: 12,
        padding: 15
      }
    },
    tooltip: {
      backgroundColor: 'rgba(10, 14, 18, 0.95)',
      titleColor: '#00ff88',
      bodyColor: '#e0e6ed',
      borderColor: '#00ff88',
      borderWidth: 1,
      titleFont: { family: "'JetBrains Mono', monospace", weight: 'bold' },
      bodyFont: { family: "'IBM Plex Sans', sans-serif" },
      padding: 12,
      cornerRadius: 0
    }
  },
  scales: {
    x: {
      ticks: {
        color: '#5a6a7a',
        font: { family: "'JetBrains Mono', monospace", size: 9 },
        maxRotation: 45,
        minRotation: 0
      },
      grid: {
        color: 'rgba(0, 255, 136, 0.05)',
        lineWidth: 1
      }
    },
    y: {
      beginAtZero: true,
      ticks: {
        color: '#5a6a7a',
        font: { family: "'JetBrains Mono', monospace", size: 10 },
        precision: 0
      },
      grid: {
        color: 'rgba(0, 255, 136, 0.08)',
        lineWidth: 1
      }
    }
  }
};

const filteredTimeline = computed(() => {
  // Group by MITRE Technique ID
  const techniqueMap = {};

  // 1. Count by technique_id from attack steps
  for (const op of filteredOperations.value) {
    for (const step of (op.attack_steps || [])) {
      if (filters.os_filter !== 'all') {
        const agentPlatform = op.agent_platforms?.[step.paw];
        if (!agentPlatform) continue;
        const platform = agentPlatform.toLowerCase();
        const filterOs = filters.os_filter.toLowerCase();
        if (platform !== filterOs && !platform.includes(filterOs)) {
          continue;
        }
      }
      const techId = step.technique_id || 'Unknown';
      if (!techniqueMap[techId]) {
        techniqueMap[techId] = { technique: techId, attacks: 0, detections: 0 };
      }
      techniqueMap[techId].attacks += 1;
    }
  }

  // 2. Count by technique_id from detection events
  filteredDetections.value.forEach(detection => {
    const techId = detection.technique_id || 'Unknown';
    if (!techniqueMap[techId]) {
      techniqueMap[techId] = { technique: techId, attacks: 0, detections: 0 };
    }
    techniqueMap[techId].detections += 1;
  });

  // Return sorted by technique_id
  return Object.values(techniqueMap).sort((a, b) => a.technique.localeCompare(b.technique));
});

const timelineChartData = computed(() => {
  const timeline = filteredTimeline.value;
  if (!timeline || timeline.length === 0) {
    return { labels: [], datasets: [] };
  }
  return {
    labels: timeline.map(d => d.technique),  // Use MITRE Technique ID as label
    datasets: [
      {
        label: 'ATTACKS',
        backgroundColor: 'rgba(255, 51, 102, 0.15)',
        borderColor: '#ff3366',
        borderWidth: 2,
        fill: true,
        tension: 0.3,
        pointRadius: 4,
        pointBackgroundColor: '#ff3366',
        pointBorderColor: '#0a0e12',
        pointBorderWidth: 2,
        pointHoverRadius: 6,
        data: timeline.map(d => d.attacks)
      },
      {
        label: 'DETECTIONS',
        backgroundColor: 'rgba(0, 255, 136, 0.15)',
        borderColor: '#00ff88',
        borderWidth: 2,
        fill: true,
        tension: 0.3,
        pointRadius: 4,
        pointBackgroundColor: '#00ff88',
        pointBorderColor: '#0a0e12',
        pointBorderWidth: 2,
        pointHoverRadius: 6,
        data: timeline.map(d => d.detections)
      }
    ]
  };
});

const timelineChartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      display: true,
      position: 'top',
      labels: {
        color: '#00ff88',
        font: { family: "'JetBrains Mono', monospace", size: 10, weight: 'bold' },
        boxWidth: 12,
        padding: 15
      }
    },
    tooltip: {
      backgroundColor: 'rgba(10, 14, 18, 0.95)',
      titleColor: '#00ff88',
      bodyColor: '#e0e6ed',
      borderColor: '#00ff88',
      borderWidth: 1,
      titleFont: { family: "'JetBrains Mono', monospace", weight: 'bold' },
      bodyFont: { family: "'IBM Plex Sans', sans-serif" },
      padding: 12,
      cornerRadius: 0
    }
  },
  scales: {
    x: {
      ticks: {
        color: '#5a6a7a',
        font: { family: "'JetBrains Mono', monospace", size: 10 }
      },
      grid: {
        color: 'rgba(0, 255, 136, 0.05)'
      }
    },
    y: {
      beginAtZero: true,
      ticks: {
        color: '#5a6a7a',
        font: { family: "'JetBrains Mono', monospace", size: 10 },
        precision: 0
      },
      grid: {
        color: 'rgba(0, 255, 136, 0.08)'
      }
    }
  }
};
</script>

<template>
  <div>
    <!-- Standard Caldera Plugin Header -->
    <h1 class="caldera-plugin-title">Bastion</h1>
    <p class="caldera-plugin-description">Breach and Attack Simulation integrated with Wazuh SIEM for automated detection validation.</p>
    <hr class="caldera-plugin-divider" />

    <div class="bastion-cyber-dashboard">
      <!-- Scanline Overlay -->
      <div class="scanline-overlay"></div>

      <!-- Grid Background -->
      <div class="grid-background"></div>

      <!-- Header Section -->
      <header class="dashboard-header">
        <div class="header-content">
          <div class="logo-section">
            <div class="logo-icon">
              <svg viewBox="0 0 100 100" class="shield-icon">
                <polygon points="50,5 95,25 95,55 50,95 5,55 5,25" fill="none" stroke="currentColor" stroke-width="3"/>
                <polygon points="50,20 80,35 80,55 50,80 20,55 20,35" fill="currentColor" opacity="0.3"/>
                <circle cx="50" cy="50" r="12" fill="none" stroke="currentColor" stroke-width="2"/>
                <circle cx="50" cy="50" r="4" fill="currentColor"/>
              </svg>
            </div>
            <div class="logo-text">
              <h1 class="main-title">BASTION</h1>
              <p class="subtitle-text">BREACH & ATTACK SIMULATION COMMAND CENTER</p>
            </div>
          </div>
          <div class="header-status">
            <div class="status-indicator online">
              <span class="pulse-ring"></span>
              <span class="status-dot"></span>
              <span class="status-text">SYSTEM ONLINE</span>
            </div>
            <div class="timestamp">{{ new Date().toLocaleString('en-US') }}</div>
          </div>
        </div>
        <div class="header-divider"></div>
      </header>

      <!-- Filters Section -->
      <section class="filters-section">
        <div class="section-header">
          <span class="section-icon">[&gt;_]</span>
          <h2 class="section-title">COMMAND FILTERS</h2>
          <button class="refresh-btn" @click="refreshData" :disabled="isLoading">
            <span class="btn-icon" :class="{ 'spinning': isLoading }">&#x21BB;</span>
            <span class="btn-text">{{ isLoading ? 'SYNCING...' : 'REFRESH' }}</span>
          </button>
        </div>
        <div class="filters-grid">
          <div class="filter-item">
            <label class="filter-label">SEARCH_QUERY</label>
            <div class="input-wrapper">
              <span class="input-prefix">&gt;</span>
              <input type="text" v-model="filters.search" placeholder="agent://technique://description" class="cyber-input">
            </div>
          </div>
          <div class="filter-item">
            <label class="filter-label">OPERATION_ID</label>
            <div class="select-wrapper">
              <select v-model="filters.operation_id" class="cyber-select">
                <option value="all">[ ALL_OPERATIONS ]</option>
                <option v-for="op in allOperations" :key="op.id" :value="op.id">
                  {{ op.name }}
                </option>
              </select>
            </div>
          </div>
          <div class="filter-item">
            <label class="filter-label">TARGET_OS</label>
            <div class="select-wrapper">
              <select v-model="filters.os_filter" class="cyber-select">
                <option value="all">[ ANY_PLATFORM ]</option>
                <option value="Windows">WINDOWS</option>
                <option value="Linux">LINUX</option>
                <option value="macOS">DARWIN</option>
              </select>
            </div>
          </div>
        </div>
      </section>

      <!-- KPI Matrix -->
      <section class="kpi-section">
        <div class="section-header">
          <span class="section-icon">[#]</span>
          <h2 class="section-title">SECURITY POSTURE MATRIX</h2>
        </div>
        <div class="kpi-grid">
          <!-- Security Score - Featured -->
          <div class="kpi-card featured" :class="securityScoreColor">
            <div class="kpi-glow"></div>
            <div class="kpi-content">
              <div class="kpi-header">
                <span class="kpi-icon">
                  <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
                  </svg>
                </span>
                <span class="kpi-label">SECURITY_SCORE</span>
              </div>
              <div class="kpi-value-wrapper">
                <span class="kpi-value large">{{ filteredKPI.security_score || 0 }}</span>
                <span class="kpi-unit">/100</span>
              </div>
              <div class="kpi-grade">
                <span class="grade-label">GRADE:</span>
                <span class="grade-value">{{ filteredKPI.security_grade || 'N/A' }}</span>
              </div>
              <div class="progress-bar">
                <div class="progress-fill" :style="{ width: (filteredKPI.security_score || 0) + '%' }"></div>
                <div class="progress-glow"></div>
              </div>
            </div>
          </div>

          <!-- Detection Rate -->
          <div class="kpi-card cyber-green">
            <div class="kpi-content">
              <div class="kpi-header">
                <span class="kpi-icon">
                  <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
                  </svg>
                </span>
                <span class="kpi-label">DETECTION_RATE</span>
              </div>
              <div class="kpi-value-wrapper">
                <span class="kpi-value">{{ filteredKPI.detection_rate || 0 }}</span>
                <span class="kpi-unit">%</span>
              </div>
            </div>
          </div>

          <!-- MTTD -->
          <div class="kpi-card cyber-blue">
            <div class="kpi-content">
              <div class="kpi-header">
                <span class="kpi-icon">
                  <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/>
                  </svg>
                </span>
                <span class="kpi-label">MTTD</span>
              </div>
              <div class="kpi-value-wrapper">
                <span class="kpi-value">{{ filteredKPI.mttd_minutes || 0 }}</span>
                <span class="kpi-unit">min</span>
              </div>
            </div>
          </div>

          <!-- Critical Gaps -->
          <div class="kpi-card cyber-red">
            <div class="kpi-content">
              <div class="kpi-header">
                <span class="kpi-icon">
                  <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>
                  </svg>
                </span>
                <span class="kpi-label">CRITICAL_GAPS</span>
              </div>
              <div class="kpi-value-wrapper">
                <span class="kpi-value">{{ filteredKPI.critical_gaps || 0 }}</span>
              </div>
            </div>
          </div>

          <!-- Tactic Coverage -->
          <div class="kpi-card cyber-purple">
            <div class="kpi-content">
              <div class="kpi-header">
                <span class="kpi-icon">
                  <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                  </svg>
                </span>
                <span class="kpi-label">TACTIC_COVERAGE</span>
              </div>
              <div class="kpi-value-wrapper">
                <span class="kpi-value">{{ filteredKPI.tactic_coverage || 0 }}</span>
                <span class="kpi-unit">/14</span>
              </div>
            </div>
          </div>

          <!-- Operations -->
          <div class="kpi-card cyber-cyan">
            <div class="kpi-content">
              <div class="kpi-header">
                <span class="kpi-icon">
                  <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M8 5v14l11-7z"/>
                  </svg>
                </span>
                <span class="kpi-label">OPERATIONS</span>
              </div>
              <div class="kpi-value-wrapper">
                <span class="kpi-value">{{ filteredKPI.total_operations }}</span>
              </div>
            </div>
          </div>

          <!-- Attack Steps -->
          <div class="kpi-card cyber-orange">
            <div class="kpi-content">
              <div class="kpi-header">
                <span class="kpi-icon">
                  <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 8c-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4-1.79-4-4-4zm8.94 3c-.46-4.17-3.77-7.48-7.94-7.94V1h-2v2.06C6.83 3.52 3.52 6.83 3.06 11H1v2h2.06c.46 4.17 3.77 7.48 7.94 7.94V23h2v-2.06c4.17-.46 7.48-3.77 7.94-7.94H23v-2h-2.06zM12 19c-3.87 0-7-3.13-7-7s3.13-7 7-7 7 3.13 7 7-3.13 7-7 7z"/>
                  </svg>
                </span>
                <span class="kpi-label">ATTACK_STEPS</span>
              </div>
              <div class="kpi-value-wrapper">
                <span class="kpi-value">{{ filteredKPI.total_attack_steps }}</span>
              </div>
            </div>
          </div>

          <!-- Detections -->
          <div class="kpi-card cyber-pink">
            <div class="kpi-content">
              <div class="kpi-header">
                <span class="kpi-icon">
                  <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.89 2 2 2zm6-6v-5c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2z"/>
                  </svg>
                </span>
                <span class="kpi-label">DETECTIONS</span>
              </div>
              <div class="kpi-value-wrapper">
                <span class="kpi-value">{{ filteredKPI.total_detections }}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- Charts Section -->
      <section class="charts-section">
        <div class="charts-grid">
          <!-- Tactic Coverage Chart -->
          <div class="chart-panel">
            <div class="panel-header">
              <span class="panel-icon">[/\]</span>
              <h3 class="panel-title">TACTIC_COVERAGE_ANALYSIS</h3>
            </div>
            <div class="chart-container">
              <Bar v-if="tacticChartData.labels.length > 0" :data="tacticChartData" :options="tacticChartOptions" />
              <div v-else class="no-data">
                <span class="no-data-icon">[ ]</span>
                <span class="no-data-text">NO_DATA_AVAILABLE</span>
              </div>
            </div>
            <div class="chart-legend">
              <span class="legend-item"><span class="legend-color red"></span>GAP (0%)</span>
              <span class="legend-item"><span class="legend-color yellow"></span>PARTIAL (1-79%)</span>
              <span class="legend-item"><span class="legend-color green"></span>COVERED (80%+)</span>
            </div>
          </div>

          <!-- Timeline Chart -->
          <div class="chart-panel">
            <div class="panel-header">
              <span class="panel-icon">[~]</span>
              <h3 class="panel-title">ATTACK_VS_DETECTION_TIMELINE</h3>
            </div>
            <div class="chart-container">
              <Line v-if="timelineChartData.labels.length > 0" :data="timelineChartData" :options="timelineChartOptions" />
              <div v-else class="no-data">
                <span class="no-data-icon">[ ]</span>
                <span class="no-data-text">NO_TIMELINE_DATA</span>
              </div>
            </div>
          </div>

          <!-- Operations Panel -->
          <div class="chart-panel operations-panel">
            <div class="panel-header">
              <span class="panel-icon">[&gt;]</span>
              <h3 class="panel-title">ACTIVE_OPERATIONS</h3>
            </div>
            <div class="operations-list">
              <div v-if="filteredOperations.length === 0" class="no-data">
                <span class="no-data-text">NO_OPERATIONS_FOUND</span>
              </div>
              <div v-else v-for="op in filteredOperations" :key="op.id" class="operation-card">
                <div class="op-header">
                  <span class="op-name">{{ op.name }}</span>
                  <span class="op-status" :class="op.state">{{ op.state?.toUpperCase() }}</span>
                </div>
                <div class="op-id">ID: {{ op.id }}</div>
                <div class="op-time">{{ formatTimestamp(op.started) }}</div>
                <div class="op-tags">
                  <span class="op-tag agents">{{ op.agent_count }} AGENTS</span>
                  <span class="op-tag steps">{{ op.attack_steps?.length || 0 }} STEPS</span>
                  <span class="op-tag techniques">{{ op.techniques?.length || 0 }} TECHNIQUES</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- MITRE ATT&CK Heat Map -->
      <section class="heatmap-section">
        <div class="section-header">
          <span class="section-icon">[*]</span>
          <h2 class="section-title">MITRE ATT&CK TECHNIQUE COVERAGE</h2>
        </div>

        <!-- Summary Cards -->
        <div class="heatmap-summary">
          <div class="summary-card">
            <span class="summary-label">TOTAL_TECHNIQUES</span>
            <span class="summary-value">{{ heatMapData.summary.total_techniques }}</span>
          </div>
          <div class="summary-card blue">
            <span class="summary-label">SIMULATED</span>
            <span class="summary-value">{{ heatMapData.summary.total_simulated }}</span>
          </div>
          <div class="summary-card green">
            <span class="summary-label">DETECTED</span>
            <span class="summary-value">{{ heatMapData.summary.total_detected }}</span>
          </div>
          <div class="summary-card" :style="{ '--accent-color': heatMapSummaryColor }">
            <span class="summary-label">DETECTION_RATE</span>
            <span class="summary-value">{{ Math.min(heatMapData.summary.overall_detection_rate || 0, 100) }}%</span>
          </div>
        </div>

        <!-- Techniques Table -->
        <div class="table-container">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>STATUS</th>
                <th>TECHNIQUE_ID</th>
                <th>NAME</th>
                <th>TACTIC</th>
                <th>SIMULATED</th>
                <th>DETECTED</th>
                <th>RATE</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="heatMapData.techniques.length === 0">
                <td colspan="7" class="no-data-row">NO_TECHNIQUE_DATA_AVAILABLE</td>
              </tr>
              <tr v-for="tech in heatMapData.techniques" :key="tech.id" :class="{ 'gap-row': tech.status === 'gap' }">
                <td>
                  <span class="status-badge" :class="tech.status">
                    {{ tech.status === 'gap' ? 'GAP' : tech.status === 'partial' ? 'PARTIAL' : tech.status === 'complete' ? 'OK' : '-' }}
                  </span>
                </td>
                <td class="technique-id">{{ tech.id }}</td>
                <td class="technique-name">{{ tech.name }}</td>
                <td><span class="tactic-badge">{{ tech.tactic }}</span></td>
                <td class="numeric">{{ tech.simulated }}</td>
                <td class="numeric" :class="{ 'zero': tech.detected === 0 }">{{ tech.detected }}</td>
                <td>
                  <div class="rate-cell">
                    <div class="mini-progress">
                      <div class="mini-progress-fill" :class="tech.status" :style="{ width: Math.min(tech.detection_rate, 100) + '%' }"></div>
                    </div>
                    <span class="rate-value">{{ Math.min(tech.detection_rate, 100) }}%</span>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- Agents Section -->
      <section class="agents-section">
        <div class="section-header">
          <span class="section-icon">[@]</span>
          <h2 class="section-title">CONNECTED_AGENTS</h2>
        </div>
        <div class="table-container">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>AGENT_ID</th>
                <th>HOSTNAME</th>
                <th>PLATFORM</th>
                <th>ATTACK_STEPS</th>
                <th>DETECTIONS</th>
                <th>COVERAGE</th>
                <th>LAST_SEEN</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="sortedAgents.length === 0">
                <td colspan="7" class="no-data-row">NO_AGENTS_CONNECTED</td>
              </tr>
              <tr v-for="agent in sortedAgents.slice(0, 20)" :key="agent.paw">
                <td class="agent-cell">
                  <span class="agent-status" :class="{ online: agent.alive, offline: !agent.alive }"></span>
                  <span class="agent-paw">{{ agent.paw }}</span>
                </td>
                <td class="hostname">{{ agent.host }}</td>
                <td><span class="platform-badge" :class="agent.platform?.toLowerCase()">{{ agent.platform }}</span></td>
                <td class="numeric">{{ agent.attack_steps_count || 0 }}</td>
                <td class="numeric">{{ agent.detections_count || 0 }}</td>
                <td class="coverage-cell">
                  <span :class="(agent.attack_steps_count > 0 && agent.detections_count > 0) ? 'good' : 'zero'">
                    {{ agent.attack_steps_count > 0 ? Math.min(100, Math.round((agent.detections_count / agent.attack_steps_count) * 100)) + '%' : '0%' }}
                  </span>
                </td>
                <td class="timestamp-cell">{{ formatTimestamp(agent.last_seen) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- Detections Section -->
      <section class="detections-section">
        <div class="section-header">
          <span class="section-icon">[!]</span>
          <h2 class="section-title">DETECTION_EVENTS</h2>
          <span class="events-count">{{ filteredDetections.length }} EVENTS</span>
          <span class="page-info">(Page {{ detectionCurrentPage }}/{{ detectionTotalPages }})</span>
          <span v-if="selectedAgentHost" class="filter-badge">
            FILTER: {{ selectedAgentHost }}
            <button class="clear-filter" @click="clearAgentFilter">X</button>
          </span>
        </div>

        <!-- Pagination Top -->
        <div class="pagination-container" v-if="filteredDetections.length > 0">
          <div class="pagination-info">
            <span class="showing-text">Showing {{ ((detectionCurrentPage - 1) * detectionPageSize) + 1 }}-{{ Math.min(detectionCurrentPage * detectionPageSize, filteredDetections.length) }} of {{ filteredDetections.length }}</span>
          </div>
          <div class="pagination-controls">
            <button class="page-btn" @click="prevDetectionPage" :disabled="detectionCurrentPage === 1">&lt; PREV</button>
            <template v-for="page in detectionPageNumbers" :key="page">
              <span v-if="page === '...'" class="page-ellipsis">...</span>
              <button v-else class="page-btn" :class="{ active: page === detectionCurrentPage }" @click="goToDetectionPage(page)">{{ page }}</button>
            </template>
            <button class="page-btn" @click="nextDetectionPage" :disabled="detectionCurrentPage === detectionTotalPages">NEXT &gt;</button>
          </div>
          <div class="page-size-selector">
            <span class="page-size-label">PER_PAGE:</span>
            <select v-model="detectionPageSize" class="page-size-select" @change="detectionCurrentPage = 1">
              <option :value="10">10</option>
              <option :value="25">25</option>
              <option :value="50">50</option>
              <option :value="100">100</option>
            </select>
          </div>
        </div>

        <div class="table-container detections-table">
          <table class="cyber-table expandable-table">
            <thead>
              <tr>
                <th class="expand-col"></th>
                <th>TIMESTAMP</th>
                <th>AGENT</th>
                <th>RULE_ID</th>
                <th>LEVEL</th>
                <th>TECHNIQUE</th>
                <th>MATCH_STATUS</th>
                <th>DESCRIPTION</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="paginatedDetections.length === 0">
                <td colspan="8" class="no-data-row">NO_DETECTION_EVENTS</td>
              </tr>
              <template v-for="(event, idx) in paginatedDetections" :key="idx">
                <tr
                  :class="{
                    'matched-row': event.match_status === 'matched',
                    'partial-row': event.match_status === 'partial',
                    'expandable-row': true,
                    'expanded': isDetectionExpanded(idx)
                  }"
                  @click="toggleDetectionDetail(idx)"
                >
                  <td class="expand-toggle">
                    <span class="expand-icon" :class="{ 'rotated': isDetectionExpanded(idx) }">&#9654;</span>
                  </td>
                  <td class="timestamp-cell">{{ formatTimestamp(event.timestamp) }}</td>
                  <td class="agent-name">{{ event.agent_name || '-' }}</td>
                  <td class="rule-id">{{ event.rule_id }}</td>
                  <td>
                    <span class="level-badge" :class="getLevelClass(event.rule_level)">{{ event.rule_level }}</span>
                  </td>
                  <td>
                    <span v-if="event.technique_id" class="technique-badge">{{ event.technique_id }}</span>
                    <span v-else class="na">-</span>
                  </td>
                  <td>
                    <span class="match-badge" :class="event.match_status">
                      {{ event.match_status === 'matched' ? 'MATCHED' : event.match_status === 'partial' ? 'PARTIAL' : 'UNMATCHED' }}
                    </span>
                  </td>
                  <td class="description-cell">{{ event.description }}</td>
                </tr>
                <!-- Expanded Detail Row -->
                <tr v-if="isDetectionExpanded(idx)" class="detail-row" :class="{ 'matched-row': event.match_status === 'matched', 'partial-row': event.match_status === 'partial' }">
                  <td colspan="8">
                    <div class="detection-detail-panel">
                      <div class="detail-header">
                        <span class="detail-title">[+] EVENT DETAILS</span>
                        <span class="detail-id">IDX: {{ idx }}</span>
                      </div>
                      <div class="detail-grid">
                        <div class="detail-section">
                          <h4 class="detail-section-title">TIME & SOURCE</h4>
                          <div class="detail-item">
                            <span class="detail-label">FULL_TIMESTAMP:</span>
                            <span class="detail-value monospace">{{ event.timestamp || 'N/A' }}</span>
                          </div>
                          <div class="detail-item">
                            <span class="detail-label">AGENT_ID:</span>
                            <span class="detail-value">{{ event.agent_id || 'N/A' }}</span>
                          </div>
                          <div class="detail-item">
                            <span class="detail-label">AGENT_NAME:</span>
                            <span class="detail-value">{{ event.agent_name || 'N/A' }}</span>
                          </div>
                          <div class="detail-item">
                            <span class="detail-label">AGENT_OS:</span>
                            <span class="detail-value">{{ event.agent_os || 'N/A' }}</span>
                          </div>
                          <div class="detail-item">
                            <span class="detail-label">SOURCE:</span>
                            <span class="detail-value">{{ event.match_source || 'wazuh' }}</span>
                          </div>
                        </div>
                        <div class="detail-section">
                          <h4 class="detail-section-title">DETECTION INFO</h4>
                          <div class="detail-item">
                            <span class="detail-label">RULE_ID:</span>
                            <span class="detail-value highlight-blue">{{ event.rule_id }}</span>
                          </div>
                          <div class="detail-item">
                            <span class="detail-label">RULE_LEVEL:</span>
                            <span class="detail-value">
                              <span class="level-badge" :class="getLevelClass(event.rule_level)">{{ event.rule_level }}</span>
                            </span>
                          </div>
                          <div class="detail-item">
                            <span class="detail-label">MITRE_TECHNIQUE:</span>
                            <span class="detail-value">
                              <span v-if="event.technique_id" class="technique-badge">{{ event.technique_id }}</span>
                              <span v-else class="na">N/A</span>
                            </span>
                          </div>
                          <div class="detail-item">
                            <span class="detail-label">TACTIC:</span>
                            <span class="detail-value">
                              <span v-if="event.tactic" class="tactic-badge">{{ event.tactic }}</span>
                              <span v-else class="na">N/A</span>
                            </span>
                          </div>
                        </div>
                        <div class="detail-section">
                          <h4 class="detail-section-title">CORRELATION</h4>
                          <div class="detail-item">
                            <span class="detail-label">MATCH_STATUS:</span>
                            <span class="detail-value">
                              <span class="match-badge large" :class="event.match_status">
                                {{ event.match_status === 'matched' ? 'MATCHED' : event.match_status === 'partial' ? 'PARTIAL' : 'UNMATCHED' }}
                              </span>
                            </span>
                          </div>
                          <div class="detail-item">
                            <span class="detail-label">ATTACK_STEP_ID:</span>
                            <span class="detail-value monospace">{{ event.attack_step_id || 'N/A' }}</span>
                          </div>
                          <div class="detail-item">
                            <span class="detail-label">OPERATION:</span>
                            <span class="detail-value monospace">{{ event.opId || 'N/A' }}</span>
                          </div>
                        </div>
                      </div>
                      <div class="detail-description">
                        <h4 class="detail-section-title">FULL DESCRIPTION</h4>
                        <div class="description-box">{{ event.description || 'No description available' }}</div>
                      </div>

                      <!-- SUMMARY Section -->
                      <div class="detail-summary">
                        <h4 class="detail-section-title">SUMMARY</h4>
                        <div class="summary-grid">
                          <div class="summary-item">
                            <span class="summary-label">Agent IP</span>
                            <span class="summary-value">{{ event.agent_ip || 'N/A' }}</span>
                          </div>
                          <div class="summary-item">
                            <span class="summary-label">Audit Command</span>
                            <span class="summary-value command-value">{{ event.audit_command || 'N/A' }}</span>
                          </div>
                          <div class="summary-item">
                            <span class="summary-label">Working Directory</span>
                            <span class="summary-value path-value">{{ event.audit_cwd || 'N/A' }}</span>
                          </div>
                          <div class="summary-item">
                            <span class="summary-label">Audit Type</span>
                            <span class="summary-value type-value">{{ event.audit_type || 'N/A' }}</span>
                          </div>
                          <div class="summary-item">
                            <span class="summary-label">Audit Executable</span>
                            <span class="summary-value exe-value">{{ event.audit_exe || 'N/A' }}</span>
                          </div>
                          <div class="summary-item">
                            <span class="summary-label">Source IP</span>
                            <span class="summary-value">{{ event.srcip || 'N/A' }}</span>
                          </div>
                          <div class="summary-item">
                            <span class="summary-label">Destination IP</span>
                            <span class="summary-value">{{ event.dstip || 'N/A' }}</span>
                          </div>
                        </div>
                      </div>

                      <!-- RAW LOG Section -->
                      <div class="detail-raw-log" v-if="event.full_log">
                        <h4 class="detail-section-title">RAW LOG</h4>
                        <pre class="raw-log-box">{{ event.full_log }}</pre>
                      </div>

                      <!-- EVENT DATA Section -->
                      <div class="detail-event-data" v-if="event.raw_data && Object.keys(event.raw_data).length > 0">
                        <h4 class="detail-section-title">EVENT DATA</h4>
                        <div class="event-data-grid">
                          <template v-for="(value, key) in flattenEventData(event.raw_data)" :key="key">
                            <div class="event-data-item">
                              <span class="event-data-key">{{ key }}:</span>
                              <span class="event-data-value">{{ formatEventValue(value) }}</span>
                            </div>
                          </template>
                        </div>
                      </div>

                      <!-- SYSCHECK Section -->
                      <div class="detail-syscheck" v-if="event.syscheck && Object.keys(event.syscheck).length > 0">
                        <h4 class="detail-section-title">FILE INTEGRITY MONITORING</h4>
                        <div class="event-data-grid">
                          <div class="event-data-item" v-if="event.syscheck.path">
                            <span class="event-data-key">path:</span>
                            <span class="event-data-value monospace">{{ event.syscheck.path }}</span>
                          </div>
                          <div class="event-data-item" v-if="event.syscheck.event">
                            <span class="event-data-key">event:</span>
                            <span class="event-data-value">{{ event.syscheck.event }}</span>
                          </div>
                          <div class="event-data-item" v-if="event.syscheck.mode">
                            <span class="event-data-key">mode:</span>
                            <span class="event-data-value">{{ event.syscheck.mode }}</span>
                          </div>
                          <div class="event-data-item" v-if="event.syscheck.size_after">
                            <span class="event-data-key">size:</span>
                            <span class="event-data-value">{{ event.syscheck.size_after }}</span>
                          </div>
                          <div class="event-data-item" v-if="event.syscheck.md5_after">
                            <span class="event-data-key">md5:</span>
                            <span class="event-data-value monospace">{{ event.syscheck.md5_after }}</span>
                          </div>
                          <div class="event-data-item" v-if="event.syscheck.sha1_after">
                            <span class="event-data-key">sha1:</span>
                            <span class="event-data-value monospace">{{ event.syscheck.sha1_after }}</span>
                          </div>
                        </div>
                      </div>

                      <!-- LOCATION Section -->
                      <div class="detail-location" v-if="event.location">
                        <h4 class="detail-section-title">LOG SOURCE</h4>
                        <div class="location-box monospace">{{ event.location }}</div>
                      </div>
                    </div>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>
      </section>

      <!-- Correlation Section -->
      <section class="correlation-section">
        <div class="section-header">
          <span class="section-icon">[&amp;]</span>
          <h2 class="section-title">OPERATION_CORRELATION_ANALYSIS</h2>
        </div>
        <div class="correlation-form">
          <div class="input-group">
            <span class="input-label">OPERATION_ID &gt;</span>
            <input type="text" v-model="correlationOperationId" placeholder="Enter Caldera Operation ID" class="cyber-input large">
            <button class="analyze-btn" @click="correlateOperation" :disabled="!correlationOperationId || isCorrelating">
              <span v-if="isCorrelating" class="btn-spinner"></span>
              <span v-else>[ANALYZE]</span>
            </button>
          </div>
          <div v-if="correlationResult" class="correlation-result">
            <div class="result-header">ANALYSIS_COMPLETE</div>
            <div class="result-content">
              <div class="result-item">
                <span class="result-label">OPERATION:</span>
                <span class="result-value">{{ correlationResult.operation_name }}</span>
              </div>
              <div class="result-item">
                <span class="result-label">DETECTION_RATE:</span>
                <span class="result-value highlight">{{ formatCoverage(correlationResult.correlation.detection_rate) }}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- Discover Section -->
      <section class="discover-section">
        <div class="section-header">
          <span class="section-icon">[?]</span>
          <h2 class="section-title">DISCOVER</h2>
        </div>
        <div class="discover-wrapper">
          <DiscoverPanel />
        </div>
      </section>

      <!-- Footer -->
      <footer class="dashboard-footer">
        <div class="footer-content">
          <span class="footer-text">BASTION v1.0 // CALDERA-WAZUH INTEGRATION</span>
          <span class="footer-divider">|</span>
          <span class="footer-text">AUTO-REFRESH: 30s</span>
        </div>
      </footer>
    </div>
  </div>
</template>

<style scoped>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

/* Standard Caldera Plugin Header Styles */
.caldera-plugin-title {
  font-size: 1.5rem;
  font-weight: 400;
  color: #d4d4d4;
  margin: 0 0 0.5rem 0;
  padding: 1rem 1.5rem 0 1.5rem;
  font-family: inherit;
}

.caldera-plugin-description {
  font-size: 0.95rem;
  color: #9ca3af;
  margin: 0;
  padding: 0 1.5rem 1rem 1.5rem;
  font-weight: 400;
}

.caldera-plugin-divider {
  border: none;
  height: 3px;
  background: linear-gradient(90deg, #7c3aed, #8b5cf6);
  margin: 0;
}

/* CSS Variables */
.bastion-cyber-dashboard {
  --bg-primary: #0a0e12;
  --bg-secondary: #0f1419;
  --bg-tertiary: #151c24;
  --bg-card: #1a222d;
  --border-color: #2a3a4a;
  --text-primary: #e0e6ed;
  --text-secondary: #8899aa;
  --text-muted: #5a6a7a;
  --cyber-green: #00ff88;
  --cyber-green-dim: rgba(0, 255, 136, 0.15);
  --cyber-blue: #00d4ff;
  --cyber-red: #ff3366;
  --cyber-yellow: #ffcc00;
  --cyber-orange: #ff9500;
  --cyber-purple: #a855f7;
  --cyber-pink: #ec4899;
  --cyber-cyan: #06b6d4;
  --glow-green: 0 0 20px rgba(0, 255, 136, 0.4);
  --glow-blue: 0 0 20px rgba(0, 212, 255, 0.4);
  --glow-red: 0 0 20px rgba(255, 51, 102, 0.4);
}

/* Base Styles */
.bastion-cyber-dashboard {
  position: relative;
  min-height: 100vh;
  background: var(--bg-primary);
  color: var(--text-primary);
  font-family: 'IBM Plex Sans', -apple-system, sans-serif;
  padding: 0;
  overflow-x: hidden;
}

/* Scanline Overlay */
.scanline-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 0, 0, 0.03) 2px,
    rgba(0, 0, 0, 0.03) 4px
  );
  pointer-events: none;
  z-index: 1000;
}

/* Grid Background */
.grid-background {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-image:
    linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
  background-size: 50px 50px;
  pointer-events: none;
  z-index: 0;
}

/* Header */
.dashboard-header {
  position: relative;
  z-index: 10;
  padding: 1.5rem 2rem;
  background: linear-gradient(180deg, var(--bg-secondary) 0%, transparent 100%);
  border-bottom: 1px solid var(--border-color);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  max-width: 1800px;
  margin: 0 auto;
}

.logo-section {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.logo-icon {
  width: 60px;
  height: 60px;
  color: var(--cyber-green);
  filter: drop-shadow(var(--glow-green));
  animation: pulse-glow 2s ease-in-out infinite;
}

@keyframes pulse-glow {
  0%, 100% { filter: drop-shadow(0 0 10px rgba(0, 255, 136, 0.4)); }
  50% { filter: drop-shadow(0 0 25px rgba(0, 255, 136, 0.8)); }
}

.shield-icon {
  width: 100%;
  height: 100%;
}

.main-title {
  font-family: 'JetBrains Mono', monospace;
  font-size: 2.5rem;
  font-weight: 700;
  color: var(--cyber-green);
  letter-spacing: 0.3em;
  text-shadow: var(--glow-green);
  margin: 0;
}

.subtitle-text {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  color: var(--text-muted);
  letter-spacing: 0.2em;
  margin: 0;
}

.header-status {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 0.5rem;
}

.status-indicator {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
}

.status-indicator.online .status-text {
  color: var(--cyber-green);
}

.status-dot {
  width: 8px;
  height: 8px;
  background: var(--cyber-green);
  border-radius: 50%;
  position: relative;
}

.pulse-ring {
  position: absolute;
  width: 16px;
  height: 16px;
  border: 2px solid var(--cyber-green);
  border-radius: 50%;
  animation: pulse-ring 1.5s ease-out infinite;
  margin-left: -4px;
  margin-top: -4px;
}

@keyframes pulse-ring {
  0% { transform: scale(0.5); opacity: 1; }
  100% { transform: scale(1.5); opacity: 0; }
}

.timestamp {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  color: var(--text-muted);
}

.header-divider {
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--cyber-green), transparent);
  margin-top: 1rem;
  opacity: 0.3;
}

/* Sections */
section {
  position: relative;
  z-index: 10;
  padding: 1.5rem 2rem;
  max-width: 1800px;
  margin: 0 auto;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1.25rem;
}

.section-icon {
  font-family: 'JetBrains Mono', monospace;
  color: var(--cyber-green);
  font-size: 1rem;
}

.section-title {
  font-family: 'JetBrains Mono', monospace;
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-primary);
  letter-spacing: 0.1em;
  margin: 0;
}

/* Filters Section */
.filters-section {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-left: 3px solid var(--cyber-green);
  margin: 1rem 2rem;
  padding: 1.25rem;
}

.filters-section .section-header {
  margin-bottom: 1rem;
}

.refresh-btn {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: transparent;
  border: 1px solid var(--cyber-green);
  color: var(--cyber-green);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  padding: 0.5rem 1rem;
  cursor: pointer;
  transition: all 0.2s;
}

.refresh-btn:hover:not(:disabled) {
  background: var(--cyber-green-dim);
  box-shadow: var(--glow-green);
}

.refresh-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-icon {
  font-size: 1rem;
}

.btn-icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.filters-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1rem;
}

.filter-item {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.filter-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  color: var(--text-muted);
  letter-spacing: 0.05em;
}

.input-wrapper {
  display: flex;
  align-items: center;
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  padding: 0 0.75rem;
}

.input-wrapper:focus-within {
  border-color: var(--cyber-green);
  box-shadow: 0 0 10px rgba(0, 255, 136, 0.2);
}

.input-prefix {
  font-family: 'JetBrains Mono', monospace;
  color: var(--cyber-green);
  margin-right: 0.5rem;
}

.cyber-input {
  flex: 1;
  background: transparent;
  border: none;
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  padding: 0.75rem 0;
  outline: none;
}

.cyber-input::placeholder {
  color: var(--text-muted);
}

.select-wrapper {
  position: relative;
}

.cyber-select {
  width: 100%;
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  padding: 0.75rem;
  cursor: pointer;
  appearance: none;
}

.cyber-select:focus {
  border-color: var(--cyber-green);
  outline: none;
  box-shadow: 0 0 10px rgba(0, 255, 136, 0.2);
}

/* KPI Section */
.kpi-section {
  padding-top: 0.5rem;
}

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
}

.kpi-card {
  position: relative;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1.25rem;
  overflow: hidden;
  transition: all 0.3s ease;
}

.kpi-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  width: 3px;
  height: 100%;
  background: var(--accent-color, var(--border-color));
}

.kpi-card:hover {
  transform: translateY(-4px);
  border-color: var(--accent-color, var(--cyber-green));
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
}

.kpi-card.featured {
  grid-column: span 2;
  background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-tertiary) 100%);
}

.kpi-card.featured::before {
  width: 4px;
}

.kpi-card.cyber-green { --accent-color: var(--cyber-green); }
.kpi-card.cyber-blue { --accent-color: var(--cyber-blue); }
.kpi-card.cyber-red { --accent-color: var(--cyber-red); }
.kpi-card.cyber-yellow { --accent-color: var(--cyber-yellow); }
.kpi-card.cyber-orange { --accent-color: var(--cyber-orange); }
.kpi-card.cyber-purple { --accent-color: var(--cyber-purple); }
.kpi-card.cyber-pink { --accent-color: var(--cyber-pink); }
.kpi-card.cyber-cyan { --accent-color: var(--cyber-cyan); }

.kpi-glow {
  position: absolute;
  top: -50%;
  right: -50%;
  width: 100%;
  height: 100%;
  background: radial-gradient(circle, var(--accent-color) 0%, transparent 70%);
  opacity: 0.05;
}

.kpi-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
}

.kpi-icon {
  width: 20px;
  height: 20px;
  color: var(--accent-color, var(--text-muted));
}

.kpi-icon svg {
  width: 100%;
  height: 100%;
}

.kpi-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  color: var(--text-muted);
  letter-spacing: 0.05em;
}

.kpi-value-wrapper {
  display: flex;
  align-items: baseline;
  gap: 0.25rem;
}

.kpi-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 2rem;
  font-weight: 700;
  color: var(--accent-color, var(--text-primary));
  line-height: 1;
}

.kpi-value.large {
  font-size: 3rem;
}

.kpi-unit {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.9rem;
  color: var(--text-muted);
}

.kpi-grade {
  margin-top: 0.5rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
}

.grade-label {
  color: var(--text-muted);
}

.grade-value {
  color: var(--accent-color);
  font-weight: 700;
  margin-left: 0.25rem;
}

.progress-bar {
  position: relative;
  height: 4px;
  background: var(--bg-primary);
  margin-top: 1rem;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: var(--accent-color, var(--cyber-green));
  transition: width 0.5s ease;
}

.progress-glow {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, var(--accent-color, var(--cyber-green)), transparent);
  animation: progress-sweep 2s linear infinite;
  opacity: 0.3;
}

@keyframes progress-sweep {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(100%); }
}

/* Charts Section */
.charts-section {
  padding-top: 0.5rem;
}

.charts-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}

.chart-panel {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1.25rem;
}

.panel-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid var(--border-color);
}

.panel-icon {
  font-family: 'JetBrains Mono', monospace;
  color: var(--cyber-green);
  font-size: 0.9rem;
}

.panel-title {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-secondary);
  letter-spacing: 0.05em;
  margin: 0;
}

.chart-container {
  height: 280px;
}

.chart-legend {
  display: flex;
  justify-content: center;
  gap: 1.5rem;
  margin-top: 1rem;
  padding-top: 0.75rem;
  border-top: 1px solid var(--border-color);
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  color: var(--text-muted);
}

.legend-color {
  width: 12px;
  height: 12px;
}

.legend-color.red { background: var(--cyber-red); }
.legend-color.yellow { background: var(--cyber-yellow); }
.legend-color.green { background: var(--cyber-green); }

.no-data {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--text-muted);
}

.no-data-icon {
  font-family: 'JetBrains Mono', monospace;
  font-size: 2rem;
  margin-bottom: 0.5rem;
}

.no-data-text {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
}

/* Operations Panel */
.operations-panel .chart-container {
  overflow-y: auto;
}

.operations-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  max-height: 280px;
  overflow-y: auto;
}

.operation-card {
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-left: 3px solid var(--cyber-blue);
  padding: 1rem;
  transition: all 0.2s;
}

.operation-card:hover {
  border-left-color: var(--cyber-green);
  background: var(--bg-secondary);
}

.op-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.op-name {
  font-family: 'IBM Plex Sans', sans-serif;
  font-weight: 600;
  color: var(--text-primary);
  font-size: 0.9rem;
}

.op-status {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  padding: 0.25rem 0.5rem;
  border: 1px solid;
}

.op-status.running {
  color: var(--cyber-yellow);
  border-color: var(--cyber-yellow);
}

.op-status.finished {
  color: var(--cyber-green);
  border-color: var(--cyber-green);
}

.op-id {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  color: var(--text-muted);
  margin-bottom: 0.25rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.op-time {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  color: var(--text-secondary);
  margin-bottom: 0.75rem;
}

.op-tags {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.op-tag {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.6rem;
  padding: 0.2rem 0.5rem;
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
}

.op-tag.agents { color: var(--cyber-blue); border-color: var(--cyber-blue); }
.op-tag.steps { color: var(--cyber-orange); border-color: var(--cyber-orange); }
.op-tag.techniques { color: var(--cyber-green); border-color: var(--cyber-green); }

/* Heat Map Section */
.heatmap-section {
  padding-top: 0.5rem;
}

.heatmap-summary {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.summary-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-left: 3px solid var(--accent-color, var(--text-muted));
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.summary-card.blue { --accent-color: var(--cyber-blue); }
.summary-card.green { --accent-color: var(--cyber-green); }

.summary-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  color: var(--text-muted);
  letter-spacing: 0.05em;
}

.summary-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--accent-color, var(--text-primary));
}

/* Tables */
.table-container {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  overflow-x: auto;
}

.cyber-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.8rem;
}

.cyber-table th {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  font-weight: 600;
  color: var(--cyber-green);
  background: var(--bg-secondary);
  padding: 0.75rem 1rem;
  text-align: left;
  border-bottom: 1px solid var(--border-color);
  letter-spacing: 0.05em;
  white-space: nowrap;
}

.cyber-table td {
  padding: 0.6rem 1rem;
  border-bottom: 1px solid var(--border-color);
  color: var(--text-secondary);
}

.cyber-table tr:hover {
  background: rgba(0, 255, 136, 0.03);
}

.cyber-table .no-data-row {
  text-align: center;
  color: var(--text-muted);
  font-family: 'JetBrains Mono', monospace;
  padding: 2rem;
}

.cyber-table .gap-row {
  background: rgba(255, 51, 102, 0.1);
  border-left: 3px solid var(--cyber-red);
}

.cyber-table .gap-row td {
  color: var(--text-primary);
}

.cyber-table .matched-row {
  background: rgba(0, 255, 136, 0.08);
}

.cyber-table .partial-row {
  background: rgba(255, 204, 0, 0.08);
}

/* Badges */
.status-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  font-weight: 600;
  padding: 0.25rem 0.5rem;
  border: 1px solid;
}

.status-badge.gap {
  color: var(--cyber-red);
  border-color: var(--cyber-red);
  background: rgba(255, 51, 102, 0.1);
}

.status-badge.partial {
  color: var(--cyber-yellow);
  border-color: var(--cyber-yellow);
  background: rgba(255, 204, 0, 0.1);
}

.status-badge.complete {
  color: var(--cyber-green);
  border-color: var(--cyber-green);
  background: rgba(0, 255, 136, 0.1);
}

.technique-id {
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  color: var(--text-primary);
}

.technique-name {
  color: var(--text-primary);
}

.tactic-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  padding: 0.2rem 0.5rem;
  background: var(--bg-primary);
  border: 1px solid var(--cyber-blue);
  color: var(--cyber-blue);
}

.numeric {
  font-family: 'JetBrains Mono', monospace;
  text-align: center;
}

.numeric.zero {
  color: var(--cyber-red);
  font-weight: 700;
}

.rate-cell {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.mini-progress {
  flex: 1;
  height: 6px;
  background: var(--bg-primary);
  overflow: hidden;
}

.mini-progress-fill {
  height: 100%;
  transition: width 0.3s;
}

.mini-progress-fill.gap { background: var(--cyber-red); }
.mini-progress-fill.partial { background: var(--cyber-yellow); }
.mini-progress-fill.complete { background: var(--cyber-green); }

.rate-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  font-weight: 600;
  min-width: 3rem;
}

/* Agent Table */
.agent-cell {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.agent-status {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.agent-status.online {
  background: var(--cyber-green);
  box-shadow: 0 0 8px var(--cyber-green);
}

.agent-status.offline {
  background: var(--cyber-red);
}

.agent-paw {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
}

.hostname {
  font-weight: 500;
  color: var(--text-primary);
}

.platform-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  padding: 0.2rem 0.5rem;
  border: 1px solid;
}

.platform-badge.windows {
  color: var(--cyber-blue);
  border-color: var(--cyber-blue);
}

.platform-badge.linux {
  color: var(--cyber-orange);
  border-color: var(--cyber-orange);
}

.platform-badge.darwin {
  color: var(--cyber-purple);
  border-color: var(--cyber-purple);
}

.coverage-cell .good {
  color: var(--cyber-green);
  font-weight: 700;
}

.coverage-cell .zero {
  color: var(--text-muted);
}

.timestamp-cell {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  color: var(--text-muted);
}

/* Detections Table */
.detections-table {
  max-height: 500px;
  overflow-y: auto;
}

.rule-id {
  font-family: 'JetBrains Mono', monospace;
}

.level-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0.2rem 0.4rem;
  min-width: 2rem;
  text-align: center;
  display: inline-block;
}

.level-badge.critical {
  background: var(--cyber-red);
  color: white;
}

.level-badge.high {
  background: var(--cyber-orange);
  color: var(--bg-primary);
}

.level-badge.medium {
  background: var(--cyber-yellow);
  color: var(--bg-primary);
}

.level-badge.low {
  background: var(--text-muted);
  color: var(--bg-primary);
}

.technique-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  padding: 0.2rem 0.5rem;
  background: rgba(255, 204, 0, 0.1);
  border: 1px solid var(--cyber-yellow);
  color: var(--cyber-yellow);
}

.match-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  font-weight: 600;
  padding: 0.25rem 0.5rem;
  border: 1px solid;
}

.match-badge.matched {
  color: var(--cyber-green);
  border-color: var(--cyber-green);
  background: rgba(0, 255, 136, 0.1);
}

.match-badge.partial {
  color: var(--cyber-yellow);
  border-color: var(--cyber-yellow);
  background: rgba(255, 204, 0, 0.1);
}

.match-badge.unmatched {
  color: var(--text-muted);
  border-color: var(--border-color);
  background: transparent;
}

.step-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.6rem;
  padding: 0.2rem 0.4rem;
  background: var(--bg-primary);
  border: 1px solid var(--cyber-cyan);
  color: var(--cyber-cyan);
  max-width: 150px;
  display: inline-block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.source-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  padding: 0.2rem 0.4rem;
  background: var(--bg-primary);
  color: var(--text-muted);
}

.na {
  color: var(--text-muted);
}

.operation-cell {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.description-cell {
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Correlation Section */
.correlation-section {
  padding-top: 0.5rem;
}

.correlation-form {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1.5rem;
}

.input-group {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.input-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
  color: var(--cyber-green);
  white-space: nowrap;
}

.cyber-input.large {
  flex: 1;
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  padding: 0.75rem 1rem;
}

.cyber-input.large:focus {
  border-color: var(--cyber-green);
  outline: none;
  box-shadow: 0 0 10px rgba(0, 255, 136, 0.2);
}

.analyze-btn {
  background: var(--cyber-green);
  border: none;
  color: var(--bg-primary);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  font-weight: 600;
  padding: 0.75rem 1.5rem;
  cursor: pointer;
  transition: all 0.2s;
}

.analyze-btn:hover:not(:disabled) {
  box-shadow: var(--glow-green);
  transform: translateY(-2px);
}

.analyze-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-spinner {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid var(--bg-primary);
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

.correlation-result {
  margin-top: 1.5rem;
  background: var(--bg-secondary);
  border: 1px solid var(--cyber-green);
  padding: 1rem;
}

.result-header {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  color: var(--cyber-green);
  margin-bottom: 0.75rem;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--border-color);
}

.result-content {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.result-item {
  display: flex;
  gap: 0.5rem;
}

.result-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
  color: var(--text-muted);
}

.result-value {
  font-family: 'IBM Plex Sans', sans-serif;
  color: var(--text-primary);
}

.result-value.highlight {
  color: var(--cyber-green);
  font-weight: 700;
}

/* Discover Section */
.discover-section {
  padding-top: 0.5rem;
}

.discover-wrapper {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  padding: 1rem;
}

/* Footer */
.dashboard-footer {
  position: relative;
  z-index: 10;
  padding: 1.5rem 2rem;
  margin-top: 2rem;
  border-top: 1px solid var(--border-color);
  background: var(--bg-secondary);
}

.footer-content {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 1rem;
}

.footer-text {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  color: var(--text-muted);
  letter-spacing: 0.1em;
}

.footer-divider {
  color: var(--border-color);
}

/* Filter Badge */
.filter-badge {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  color: var(--cyber-cyan);
  background: rgba(6, 182, 212, 0.1);
  border: 1px solid var(--cyber-cyan);
  padding: 0.25rem 0.75rem;
  margin-left: auto;
}

.clear-filter {
  background: transparent;
  border: none;
  color: var(--cyber-red);
  cursor: pointer;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 700;
}

/* Events Count Badge */
.events-count {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  color: var(--cyber-cyan);
  background: rgba(6, 182, 212, 0.1);
  border: 1px solid var(--cyber-cyan);
  padding: 0.25rem 0.75rem;
  margin-left: 1rem;
}

/* Expandable Table Styles */
.expandable-table .expand-col {
  width: 30px;
  min-width: 30px;
}

.expandable-row {
  cursor: pointer;
  transition: background-color 0.2s ease;
}

.expandable-row:hover {
  background: rgba(0, 255, 136, 0.08) !important;
}

.expandable-row.expanded {
  background: rgba(0, 212, 255, 0.08) !important;
}

.expand-toggle {
  text-align: center;
  padding: 0.6rem 0.5rem !important;
}

.expand-icon {
  display: inline-block;
  color: var(--cyber-green);
  font-size: 0.7rem;
  transition: transform 0.2s ease;
}

.expand-icon.rotated {
  transform: rotate(90deg);
}

/* Detail Row Styles */
.detail-row {
  background: var(--bg-secondary) !important;
}

.detail-row td {
  padding: 0 !important;
  border-bottom: 2px solid var(--cyber-green);
}

.detection-detail-panel {
  padding: 1.25rem;
  background: linear-gradient(135deg, var(--bg-tertiary) 0%, var(--bg-secondary) 100%);
  border-left: 3px solid var(--cyber-green);
  margin: 0;
}

.detail-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-bottom: 0.75rem;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--border-color);
}

.detail-title {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--cyber-green);
  letter-spacing: 0.05em;
}

.detail-id {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  color: var(--text-muted);
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1.5rem;
  margin-bottom: 1rem;
}

.detail-section {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1rem;
}

.detail-section-title {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  font-weight: 600;
  color: var(--cyber-blue);
  letter-spacing: 0.05em;
  margin: 0 0 0.75rem 0;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--border-color);
}

.detail-item {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.5rem;
  gap: 0.5rem;
}

.detail-item:last-child {
  margin-bottom: 0;
}

.detail-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  color: var(--text-muted);
  white-space: nowrap;
  flex-shrink: 0;
}

.detail-value {
  font-family: 'IBM Plex Sans', sans-serif;
  font-size: 0.8rem;
  color: var(--text-primary);
  text-align: right;
  word-break: break-word;
}

.detail-value.monospace {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
}

.detail-value.highlight-blue {
  color: var(--cyber-blue);
  font-weight: 600;
}

.match-badge.large {
  padding: 0.3rem 0.75rem;
  font-size: 0.75rem;
}

.detail-description {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1rem;
}

.description-box {
  font-family: 'IBM Plex Sans', sans-serif;
  font-size: 0.85rem;
  color: var(--text-primary);
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
  background: var(--bg-primary);
  padding: 0.75rem;
  border-left: 2px solid var(--cyber-yellow);
}

/* SUMMARY Section */
.detail-summary {
  margin-top: 1rem;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1rem;
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 0.75rem;
}

.summary-item {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  padding: 0.5rem 0.75rem;
  background: var(--bg-primary);
  border-left: 3px solid var(--cyber-cyan);
  border-radius: 0 4px 4px 0;
}

.summary-label {
  font-size: 0.7rem;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.summary-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  color: var(--text-primary);
  word-break: break-all;
}

.summary-value.command-value {
  color: var(--cyber-red);
  background: rgba(255, 51, 102, 0.1);
  padding: 0.25rem 0.5rem;
  border-radius: 3px;
}

.summary-value.path-value {
  color: var(--cyber-yellow);
}

.summary-value.type-value {
  color: var(--cyber-cyan);
  font-weight: 600;
}

.summary-value.exe-value {
  color: var(--cyber-green);
}

/* RAW LOG Section */
.detail-raw-log {
  margin-top: 1rem;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1rem;
}

.raw-log-box {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
  color: var(--cyber-green);
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
  background: #0a0f14;
  padding: 1rem;
  border-left: 3px solid var(--cyber-green);
  margin: 0;
  max-height: 200px;
  overflow-y: auto;
}

/* EVENT DATA Section */
.detail-event-data,
.detail-syscheck {
  margin-top: 1rem;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1rem;
}

.event-data-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 0.5rem;
}

.event-data-item {
  display: flex;
  align-items: flex-start;
  padding: 0.4rem 0.6rem;
  background: var(--bg-primary);
  border-left: 2px solid var(--cyber-blue);
  font-size: 0.8rem;
}

.event-data-key {
  color: var(--cyber-blue);
  font-weight: 600;
  min-width: 150px;
  margin-right: 0.5rem;
  flex-shrink: 0;
}

.event-data-value {
  color: var(--text-primary);
  word-break: break-all;
  flex: 1;
}

.event-data-value.monospace {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
}

/* LOCATION Section */
.detail-location {
  margin-top: 1rem;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1rem;
}

.location-box {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
  color: var(--text-secondary);
  background: var(--bg-primary);
  padding: 0.5rem 0.75rem;
  border-left: 2px solid var(--cyber-purple);
}

@media (max-width: 1200px) {
  .detail-grid {
    grid-template-columns: 1fr;
  }
  .event-data-grid {
    grid-template-columns: 1fr;
  }
}

/* Scrollbar */
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}

::-webkit-scrollbar-track {
  background: var(--bg-primary);
}

::-webkit-scrollbar-thumb {
  background: var(--border-color);
}

::-webkit-scrollbar-thumb:hover {
  background: var(--cyber-green);
}

/* Responsive */
@media (max-width: 1200px) {
  .charts-grid {
    grid-template-columns: 1fr;
  }

  .heatmap-summary {
    grid-template-columns: repeat(2, 1fr);
  }

  .kpi-card.featured {
    grid-column: span 1;
  }
}

@media (max-width: 768px) {
  .header-content {
    flex-direction: column;
    text-align: center;
    gap: 1rem;
  }

  .header-status {
    align-items: center;
  }

  .filters-grid {
    grid-template-columns: 1fr;
  }

  .kpi-grid {
    grid-template-columns: repeat(2, 1fr);
  }

  .heatmap-summary {
    grid-template-columns: 1fr;
  }

  .input-group {
    flex-direction: column;
    align-items: stretch;
  }
}

/* Pagination Styles */
.pagination-container {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 0;
  border-bottom: 1px solid var(--border-color);
  background: var(--bg-secondary);
  margin: 0 -1rem;
  padding-left: 1rem;
  padding-right: 1rem;
}

.pagination-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.showing-text {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  color: var(--text-muted);
}

.pagination-controls {
  display: flex;
  align-items: center;
  gap: 0.25rem;
}

.page-btn {
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  color: var(--text-secondary);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  padding: 0.4rem 0.75rem;
  cursor: pointer;
  transition: all 0.2s;
  min-width: 2.5rem;
  text-align: center;
}

.page-btn:hover:not(:disabled):not(.active) {
  background: var(--bg-tertiary);
  border-color: var(--cyber-green);
  color: var(--cyber-green);
}

.page-btn.active {
  background: var(--cyber-green);
  border-color: var(--cyber-green);
  color: var(--bg-primary);
  font-weight: 600;
}

.page-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.page-ellipsis {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  color: var(--text-muted);
  padding: 0 0.5rem;
}

.page-size-selector {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.page-size-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  color: var(--text-muted);
}

.page-size-select {
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  padding: 0.4rem 0.5rem;
  cursor: pointer;
  appearance: none;
  -webkit-appearance: none;
  -moz-appearance: none;
  min-width: 60px;
}

.page-size-select:focus {
  outline: none;
  border-color: var(--cyber-green);
}

.page-info {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  color: var(--text-muted);
  margin-left: 1rem;
}

@media (max-width: 768px) {
  .pagination-container {
    flex-direction: column;
    gap: 0.75rem;
  }

  .pagination-controls {
    order: -1;
  }
}
</style>
