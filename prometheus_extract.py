#!/usr/bin/env python3
"""
Prometheus Attack Surface Enumerator
A comprehensive reconnaissance tool for Prometheus servers.
"""
import argparse
import csv
import json
import re
import sys
from collections import defaultdict, Counter
from urllib.parse import urljoin, urlparse
from datetime import datetime, timedelta

try:
    import requests
    from requests.exceptions import RequestException, Timeout
except ImportError:
    requests = None
    RequestException = Exception
    Timeout = Exception


# Regex patterns
METRIC_LINE_RE = re.compile(
    r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)'
    r'(?:\{(?P<labels>.*?)\})?'
    r'\s+'
    r'(?P<value>[-+]?((\d+(\.\d*)?)|(\.\d+))([eE][-+]?\d+)?|NaN|Inf|\+Inf|-Inf)'
    r'(?:\s+(?P<timestamp>\d+))?'
    r'$'
)

LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PRIVATE_IPV4_RE = re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')
HOSTNAME_RE = re.compile(r'\b[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.?(?:local|internal|lan|corp|private)\b', re.IGNORECASE)

# Sensitive keywords
SENSITIVE_WORDS = [
    'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key', 'access_key',
    'private_key', 'client_secret', 'auth', 'bearer', 'credential', 'session', 'jwt',
    'cookie', 'key', 'dsn', 'connection_string', 'aws_secret', 'aws_access'
]

# Prometheus API endpoints to enumerate
API_ENDPOINTS = [
    '/api/v1/status/config',
    '/api/v1/status/runtimeinfo',
    '/api/v1/status/buildinfo',
    '/api/v1/status/flags',
    '/api/v1/targets',
    '/api/v1/targets/metadata',
    '/api/v1/rules',
    '/api/v1/alerts',
    '/api/v1/alertmanagers',
    '/api/v1/label/__name__/values',
    '/api/v1/labels',
    '/api/v1/metadata',
    '/api/v1/query',
    '/api/v1/query_range',
    '/api/v1/series',
    '/federate',
    '/metrics',
    '/graph',
    '/config',
    '/flags',
    '/debug/pprof/',
    '/debug/fgprof',
    '/service-discovery',
    '/-/healthy',
    '/-/ready',
]


def format_bytes(bytes_val):
    """Format bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} PB"


def format_duration(seconds):
    """Format seconds to human readable duration."""
    if seconds is None:
        return "N/A"
    return str(timedelta(seconds=int(seconds)))


class PrometheusAPIClient:
    """Client for interacting with Prometheus HTTP API."""
    
    def __init__(self, base_url, timeout=15, headers=None):
        if requests is None:
            raise RuntimeError('requests library is required. Install: pip install requests')
        
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.headers = headers or {}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
    def _get(self, endpoint, params=None):
        """Make GET request to endpoint."""
        url = urljoin(self.base_url, endpoint)
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            return {
                'url': url,
                'status_code': resp.status_code,
                'success': resp.status_code == 200,
                'content': resp.text,
                'headers': dict(resp.headers),
                'error': None
            }
        except Timeout:
            return {
                'url': url,
                'status_code': None,
                'success': False,
                'content': None,
                'error': 'Timeout'
            }
        except RequestException as e:
            return {
                'url': url,
                'status_code': None,
                'success': False,
                'content': None,
                'error': str(e)
            }
    
    def _get_json(self, endpoint, params=None):
        """Make GET request and parse JSON response."""
        result = self._get(endpoint, params)
        if result['success']:
            try:
                result['data'] = json.loads(result['content'])
                return result
            except json.JSONDecodeError as e:
                result['error'] = f'JSON decode error: {e}'
                result['success'] = False
        return result
    
    def discover_endpoints(self):
        """Discover available endpoints."""
        print('[+] Enumerating Prometheus API endpoints...')
        results = {}
        
        for endpoint in API_ENDPOINTS:
            result = self._get(endpoint)
            results[endpoint] = {
                'accessible': result['success'],
                'status_code': result['status_code'],
                'error': result['error']
            }
            
            if result['success']:
                print(f'  [OK] {endpoint} - ACCESSIBLE')
            else:
                status = result['status_code'] or 'ERROR'
                print(f'  [--] {endpoint} - {status}')
        
        return results
    
    def get_buildinfo(self):
        """Get Prometheus build information."""
        result = self._get_json('/api/v1/status/buildinfo')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', {})
        return None
    
    def get_runtimeinfo(self):
        """Get Prometheus runtime information."""
        result = self._get_json('/api/v1/status/runtimeinfo')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', {})
        return None
    
    def get_config(self):
        """Get Prometheus configuration."""
        result = self._get_json('/api/v1/status/config')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', {})
        return None
    
    def get_flags(self):
        """Get Prometheus command-line flags."""
        result = self._get_json('/api/v1/status/flags')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', {})
        return None
    
    def get_targets(self):
        """Get active and dropped targets."""
        result = self._get_json('/api/v1/targets')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', {})
        return None
    
    def get_targets_metadata(self):
        """Get metadata about targets."""
        result = self._get_json('/api/v1/targets/metadata')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', [])
        return None
    
    def get_rules(self):
        """Get recording and alerting rules."""
        result = self._get_json('/api/v1/rules')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', {})
        return None
    
    def get_alerts(self):
        """Get active alerts."""
        result = self._get_json('/api/v1/alerts')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', {}).get('alerts', [])
        return None
    
    def get_alertmanagers(self):
        """Get Alertmanager discovery."""
        result = self._get_json('/api/v1/alertmanagers')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', {})
        return None
    
    def get_label_names(self):
        """Get all label names."""
        result = self._get_json('/api/v1/labels')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', [])
        return None
    
    def get_label_values(self, label_name):
        """Get all values for a specific label."""
        result = self._get_json(f'/api/v1/label/{label_name}/values')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', [])
        return None
    
    def query(self, query_string):
        """Execute PromQL instant query."""
        result = self._get_json('/api/v1/query', params={'query': query_string})
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', {})
        return None
    
    def get_all_metric_names(self):
        """Get all metric names from label values."""
        return self.get_label_values('__name__')
    
    def get_metadata(self):
        """Get metadata about metrics."""
        result = self._get_json('/api/v1/metadata')
        if result['success'] and result['data'].get('status') == 'success':
            return result['data'].get('data', {})
        return None
    
    def check_federation(self):
        """Check if federation endpoint is accessible."""
        result = self._get('/federate', params={'match[]': 'up'})
        return result['success']


class PrometheusEnumerator:
    """High-level enumeration and analysis of Prometheus server."""
    
    def __init__(self, api_client, metrics_parser):
        self.api = api_client
        self.parser = metrics_parser
        self.metrics = metrics_parser.metrics if metrics_parser else {}
        
    def enumerate_all(self):
        """Perform comprehensive enumeration."""
        print('\n[+] Starting comprehensive Prometheus enumeration...\n')
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': self.api.base_url if self.api else 'file',
            'endpoints': {},
            'prometheus_info': {},
            'targets': {},
            'service_discovery': {},
            'rules_alerts': {},
            'labels_and_series': {},
            'security': {},
            'performance': {},
            'interesting_findings': [],
            # Raw data for full-output mode
            'raw_config': None,
            'raw_flags': None,
            'raw_metadata': None,
        }
        
        if self.api:
            # Endpoint discovery
            results['endpoints'] = self.api.discover_endpoints()
            
            # Prometheus server info
            results['prometheus_info'] = self._extract_prometheus_info()
            
            # Store raw config and flags for full output
            results['raw_config'] = self.api.get_config()
            results['raw_flags'] = self.api.get_flags()
            results['raw_metadata'] = self.api.get_metadata()
            
            # Targets enumeration
            results['targets'] = self._extract_targets()
            
            # Service discovery
            results['service_discovery'] = self._extract_service_discovery()
            
            # Rules and alerts
            results['rules_alerts'] = self._extract_rules_alerts()
            
            # Labels and series
            results['labels_and_series'] = self._extract_labels_series()
            
            # Security checks
            results['security'] = self._extract_security_info()
            
            # Performance stats
            results['performance'] = self._extract_performance_stats()
        
        # Extract from metrics
        if self.metrics:
            results['metrics_analysis'] = self._analyze_metrics()
        
        # Compile interesting findings
        results['interesting_findings'] = self._compile_interesting_findings(results)
        
        return results
    
    def _extract_prometheus_info(self):
        """Extract Prometheus server information."""
        print('[+] Extracting Prometheus server information...')
        
        info = {
            'build': self.api.get_buildinfo(),
            'runtime': self.api.get_runtimeinfo(),
            'flags': self.api.get_flags(),
        }
        
        # Extract key stats from metrics
        if self.metrics:
            info['version'] = self._get_metric_value('prometheus_build_info', 'version')
            info['go_version'] = self._get_metric_value('prometheus_build_info', 'goversion')
            info['memory_bytes'] = self._get_metric_value('process_resident_memory_bytes')
            info['open_fds'] = self._get_metric_value('process_open_fds')
            info['goroutines'] = self._get_metric_value('go_goroutines')
            info['tsdb_blocks'] = self._get_metric_value('prometheus_tsdb_blocks_loaded')
            info['tsdb_storage_size_bytes'] = self._get_metric_value('prometheus_tsdb_storage_blocks_bytes')
            info['wal_size_bytes'] = self._get_metric_value('prometheus_tsdb_wal_storage_size_bytes')
            info['retention_duration'] = self._get_metric_label('prometheus_tsdb_retention_limit_seconds', 'retention')
        
        # Store raw config for full-output mode
        config = self.api.get_config()
        if config:
            info['config'] = config
        
        return info
    
    def _extract_targets(self):
        """Extract and enumerate scrape targets."""
        print('[+] Enumerating scrape targets...')
        
        targets_data = self.api.get_targets()
        if not targets_data:
            return {}
        
        active_targets = targets_data.get('activeTargets', [])
        dropped_targets = targets_data.get('droppedTargets', [])
        
        # Analyze active targets
        jobs = defaultdict(list)
        instances = []
        health_status = {'up': 0, 'down': 0, 'unknown': 0}
        
        for target in active_targets:
            job = target.get('labels', {}).get('job', 'unknown')
            instance = target.get('labels', {}).get('instance', '')
            health = target.get('health', 'unknown')
            
            jobs[job].append(target)
            instances.append(instance)
            health_status[health] = health_status.get(health, 0) + 1
        
        return {
            'total_active': len(active_targets),
            'total_dropped': len(dropped_targets),
            'health_status': health_status,
            'jobs': dict(jobs),
            'job_names': list(jobs.keys()),
            'unique_instances': list(set(instances)),
            'active_targets': active_targets,
            'dropped_targets': dropped_targets[:50],  # Limit to prevent spam
        }
    
    def _extract_service_discovery(self):
        """Extract service discovery information from config and targets."""
        print('[+] Analyzing service discovery configuration...')
        
        config = self.api.get_config()
        if not config:
            return {}
        
        config_yaml = config.get('yaml', '')
        
        discovery_types = {
            'kubernetes_sd_configs': 'kubernetes_sd_configs' in config_yaml,
            'consul_sd_configs': 'consul_sd_configs' in config_yaml,
            'ec2_sd_configs': 'ec2_sd_configs' in config_yaml,
            'azure_sd_configs': 'azure_sd_configs' in config_yaml,
            'gce_sd_configs': 'gce_sd_configs' in config_yaml,
            'dns_sd_configs': 'dns_sd_configs' in config_yaml,
            'file_sd_configs': 'file_sd_configs' in config_yaml,
            'static_configs': 'static_configs' in config_yaml,
            'nomad_sd_configs': 'nomad_sd_configs' in config_yaml,
        }
        
        # Extract Kubernetes-specific info from labels
        k8s_info = self._extract_kubernetes_info()
        
        return {
            'discovery_types': discovery_types,
            'enabled_mechanisms': [k for k, v in discovery_types.items() if v],
            'kubernetes': k8s_info,
            'config_available': config is not None,
        }
    
    def _extract_kubernetes_info(self):
        """Extract Kubernetes-specific information from targets."""
        targets_data = self.api.get_targets()
        if not targets_data:
            return {}
        
        namespaces = set()
        pods = set()
        nodes = set()
        services = set()
        
        for target in targets_data.get('activeTargets', []):
            labels = target.get('labels', {})
            
            if 'namespace' in labels:
                namespaces.add(labels['namespace'])
            if 'pod' in labels:
                pods.add(labels['pod'])
            if 'node' in labels:
                nodes.add(labels['node'])
            if 'service' in labels:
                services.add(labels['service'])
        
        return {
            'namespaces': sorted(namespaces),
            'pods': sorted(pods),
            'nodes': sorted(nodes),
            'services': sorted(services),
            'namespace_count': len(namespaces),
            'pod_count': len(pods),
            'node_count': len(nodes),
        }
    
    def _extract_rules_alerts(self):
        """Extract rules and active alerts."""
        print('[+] Extracting rules and alerts...')
        
        rules = self.api.get_rules()
        alerts = self.api.get_alerts()
        alertmanagers = self.api.get_alertmanagers()
        
        result = {
            'rules': rules,
            'active_alerts': alerts,
            'alertmanagers': alertmanagers,
        }
        
        if rules:
            groups = rules.get('groups', [])
            result['rule_groups_count'] = len(groups)
            result['total_rules'] = sum(len(g.get('rules', [])) for g in groups)
            
            recording_rules = []
            alerting_rules = []
            
            for group in groups:
                for rule in group.get('rules', []):
                    if rule.get('type') == 'recording':
                        recording_rules.append(rule)
                    elif rule.get('type') == 'alerting':
                        alerting_rules.append(rule)
            
            result['recording_rules_count'] = len(recording_rules)
            result['alerting_rules_count'] = len(alerting_rules)
        
        if alerts:
            result['active_alerts_count'] = len(alerts)
            result['alerts_by_severity'] = Counter([a.get('labels', {}).get('severity', 'none') for a in alerts])
        
        if alertmanagers:
            active_am = alertmanagers.get('activeAlertmanagers', [])
            result['alertmanager_count'] = len(active_am)
            result['alertmanager_urls'] = [am.get('url') for am in active_am]
        
        return result
    
    def _extract_labels_series(self):
        """Extract label names, interesting values, and series info."""
        print('[+] Analyzing labels and series...')
        
        labels = self.api.get_label_names()
        metric_names = self.api.get_all_metric_names()
        
        result = {
            'all_labels': labels,
            'label_count': len(labels) if labels else 0,
            'metric_count': len(metric_names) if metric_names else 0,
            'interesting_labels': {},
        }
        
        # Extract interesting label values
        interesting_label_names = [
            'instance', 'job', 'namespace', 'pod', 'node', 'service',
            'cluster', 'environment', 'region', 'zone', 'deployment'
        ]
        
        if labels:
            for label_name in interesting_label_names:
                if label_name in labels:
                    values = self.api.get_label_values(label_name)
                    if values:
                        result['interesting_labels'][label_name] = values[:100]  # Limit results
        
        return result
    
    def _extract_security_info(self):
        """Extract security-relevant information."""
        print('[+] Performing security checks...')
        
        config = self.api.get_config()
        flags = self.api.get_flags()
        
        security = {
            'pprof_accessible': self.api._get('/debug/pprof/').get('success', False),
            'fgprof_accessible': self.api._get('/debug/fgprof').get('success', False),
            'config_accessible': config is not None,
            'federation_enabled': self.api.check_federation(),
            'sensitive_findings': [],
        }
        
        # Check for sensitive data in config
        if config:
            config_yaml = config.get('yaml', '')
            for word in SENSITIVE_WORDS:
                if word in config_yaml.lower():
                    security['sensitive_findings'].append(f'Keyword "{word}" found in config')
        
        # Check flags for security settings
        if flags:
            security['web_external_url'] = flags.get('web.external-url')
            security['web_enable_admin_api'] = flags.get('web.enable-admin-api', 'false') == 'true'
            security['web_enable_lifecycle'] = flags.get('web.enable-lifecycle', 'false') == 'true'
        
        # Extract private IPs and hostnames
        security['private_ips'] = self._extract_private_ips()
        security['internal_hostnames'] = self._extract_internal_hostnames()
        
        return security
    
    def _extract_performance_stats(self):
        """Extract performance-related statistics from metrics."""
        print('[+] Analyzing performance metrics...')
        
        if not self.metrics:
            return {}
        
        stats = {}
        
        # Query statistics
        stats['query_duration_99p'] = self._get_metric_value('prometheus_engine_query_duration_seconds', quantile='0.99')
        stats['query_duration_50p'] = self._get_metric_value('prometheus_engine_query_duration_seconds', quantile='0.5')
        stats['queries_total'] = self._get_metric_value('prometheus_engine_queries')
        
        # Scrape statistics
        stats['scrape_pools'] = self._get_metric_value('prometheus_target_scrape_pools_total')
        stats['scrape_duration_seconds'] = self._get_metric_value('prometheus_target_interval_length_seconds')
        
        # TSDB statistics
        stats['tsdb_head_samples'] = self._get_metric_value('prometheus_tsdb_head_samples')
        stats['tsdb_head_series'] = self._get_metric_value('prometheus_tsdb_head_series')
        stats['tsdb_head_chunks'] = self._get_metric_value('prometheus_tsdb_head_chunks')
        stats['tsdb_compactions_total'] = self._get_metric_value('prometheus_tsdb_compactions_total')
        
        # Remote write/read
        stats['remote_write_enabled'] = 'prometheus_remote_storage_samples_total' in self.metrics
        stats['remote_read_enabled'] = 'prometheus_remote_storage_read_queries_total' in self.metrics
        
        return stats
    
    def _analyze_metrics(self):
        """Analyze the raw metrics for interesting patterns."""
        if not self.metrics:
            return {}
        
        extractor = Extractor(self.metrics)
        return extractor.extract_interesting_findings()
    
    def _compile_interesting_findings(self, results):
        """Compile the most interesting findings for operator attention."""
        findings = []
        
        # Prometheus version and health
        prom_info = results.get('prometheus_info', {})
        if prom_info.get('version'):
            findings.append(f"Prometheus Version: {prom_info['version']}")
        if prom_info.get('go_version'):
            findings.append(f"Go Version: {prom_info['go_version']}")
        
        # Memory and resource usage
        if prom_info.get('memory_bytes'):
            findings.append(f"Memory Usage: {format_bytes(prom_info['memory_bytes'])}")
        if prom_info.get('open_fds'):
            findings.append(f"Open File Descriptors: {prom_info['open_fds']}")
        
        # TSDB stats
        if prom_info.get('tsdb_storage_size_bytes'):
            findings.append(f"TSDB Storage Size: {format_bytes(prom_info['tsdb_storage_size_bytes'])}")
        if prom_info.get('wal_size_bytes'):
            findings.append(f"WAL Size: {format_bytes(prom_info['wal_size_bytes'])}")
        
        # Target health
        targets = results.get('targets', {})
        if targets:
            findings.append(f"Active Targets: {targets.get('total_active', 0)}")
            findings.append(f"Failed Targets: {targets.get('health_status', {}).get('down', 0)}")
            findings.append(f"Scrape Jobs: {len(targets.get('job_names', []))}")
        
        # Kubernetes
        k8s = results.get('service_discovery', {}).get('kubernetes', {})
        if k8s.get('namespace_count', 0) > 0:
            findings.append(f"Kubernetes Namespaces: {k8s['namespace_count']}")
            findings.append(f"Kubernetes Pods: {k8s['pod_count']}")
            findings.append(f"Kubernetes Nodes: {k8s['node_count']}")
        
        # Alerts
        rules_alerts = results.get('rules_alerts', {})
        if rules_alerts.get('active_alerts_count', 0) > 0:
            findings.append(f"Active Alerts: {rules_alerts['active_alerts_count']}")
        if rules_alerts.get('total_rules', 0) > 0:
            findings.append(f"Total Rules: {rules_alerts['total_rules']}")
        
        # Security
        security = results.get('security', {})
        if security.get('pprof_accessible'):
            findings.append("[!] pprof Debug Endpoint Exposed")
        if security.get('federation_enabled'):
            findings.append("Federation Endpoint Enabled")
        if security.get('web_enable_admin_api'):
            findings.append("[!] Admin API Enabled")
        
        # Service discovery
        sd = results.get('service_discovery', {})
        enabled_sd = sd.get('enabled_mechanisms', [])
        if enabled_sd:
            findings.append(f"Service Discovery: {', '.join(enabled_sd)}")
        
        return findings
    
    def _get_metric_value(self, metric_name, label_key=None, label_value=None, quantile=None):
        """Helper to get a specific metric value."""
        items = self.metrics.get(metric_name, [])
        if not items:
            return None
        
        for item in items:
            labels = item.get('labels', {})
            
            # Filter by label if specified
            if label_key and labels.get(label_key) != label_value:
                continue
            
            # Filter by quantile if specified
            if quantile and labels.get('quantile') != quantile:
                continue
            
            return item.get('value')
        
        # Return first value if no specific match
        return items[0].get('value') if items else None
    
    def _get_metric_label(self, metric_name, label_key):
        """Helper to get a specific label value from a metric."""
        items = self.metrics.get(metric_name, [])
        if not items:
            return None
        
        labels = items[0].get('labels', {})
        return labels.get(label_key)
    
    def _extract_private_ips(self):
        """Extract private IP addresses from all data."""
        ips = set()
        
        # From targets
        targets_data = self.api.get_targets()
        if targets_data:
            for target in targets_data.get('activeTargets', []) + targets_data.get('droppedTargets', []):
                instance = target.get('labels', {}).get('instance', '')
                for ip in PRIVATE_IPV4_RE.findall(instance):
                    ips.add(ip)
        
        # From metrics
        if self.metrics:
            for metric_name, items in self.metrics.items():
                for item in items:
                    for label_value in item.get('labels', {}).values():
                        for ip in PRIVATE_IPV4_RE.findall(str(label_value)):
                            ips.add(ip)
        
        return sorted(ips)
    
    def _extract_internal_hostnames(self):
        """Extract internal hostnames."""
        hostnames = set()
        
        # From targets
        targets_data = self.api.get_targets()
        if targets_data:
            for target in targets_data.get('activeTargets', []) + targets_data.get('droppedTargets', []):
                instance = target.get('labels', {}).get('instance', '')
                for hostname in HOSTNAME_RE.findall(instance):
                    if isinstance(hostname, tuple):
                        hostname = hostname[0]
                    hostnames.add(hostname)
        
        return sorted(hostnames)


class HTMLReport:
    """Generate HTML reports with modern CSS styling."""
    
    @staticmethod
    def generate(results, output_path):
        """Generate complete HTML report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prometheus Attack Surface Report - {results.get('target', 'Unknown')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .target {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .header .timestamp {{
            font-size: 0.9em;
            opacity: 0.8;
            margin-top: 10px;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section-title {{
            font-size: 1.8em;
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        
        .subsection {{
            margin-bottom: 25px;
        }}
        
        .subsection-title {{
            font-size: 1.3em;
            color: #555;
            margin-bottom: 15px;
            padding-left: 10px;
            border-left: 4px solid #667eea;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .info-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }}
        
        .info-card .label {{
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }}
        
        .info-card .value {{
            font-size: 1.5em;
            font-weight: bold;
            color: #333;
        }}
        
        .findings-list {{
            list-style: none;
        }}
        
        .finding-item {{
            padding: 12px 15px;
            margin-bottom: 8px;
            border-radius: 4px;
            background: #f8f9fa;
            border-left: 4px solid #667eea;
        }}
        
        .finding-critical {{
            background: #fee;
            border-left-color: #dc3545;
        }}
        
        .finding-high {{
            background: #fff3cd;
            border-left-color: #ffc107;
        }}
        
        .finding-medium {{
            background: #d1ecf1;
            border-left-color: #17a2b8;
        }}
        
        .finding-info {{
            background: #f8f9fa;
            border-left-color: #6c757d;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            margin-right: 8px;
        }}
        
        .badge-critical {{
            background: #dc3545;
            color: white;
        }}
        
        .badge-high {{
            background: #ffc107;
            color: #333;
        }}
        
        .badge-medium {{
            background: #17a2b8;
            color: white;
        }}
        
        .badge-info {{
            background: #6c757d;
            color: white;
        }}
        
        .badge-success {{
            background: #28a745;
            color: white;
        }}
        
        .badge-warning {{
            background: #fd7e14;
            color: white;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: white;
            font-size: 0.9em;
        }}
        
        th {{
            background: #667eea;
            color: white;
            padding: 8px 12px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 6px 12px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        details {{
            margin: 15px 0;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 10px;
            background: #f8f9fa;
        }}
        
        details summary {{
            cursor: pointer;
            font-weight: 600;
            padding: 8px;
            background: #667eea;
            color: white;
            border-radius: 4px;
            user-select: none;
        }}
        
        details summary:hover {{
            background: #5568d3;
        }}
        
        details[open] summary {{
            margin-bottom: 15px;
        }}
        
        .compact-list {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        
        .compact-list li {{
            padding: 3px 0;
            font-size: 0.9em;
        }}
        
        .tip-box {{
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }}
        
        .tip-box strong {{
            color: #2196F3;
        }}
        
        .action-box {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }}
        
        .action-box strong {{
            color: #f57c00;
        }}
        
        .warning-box {{
            background: #fee;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }}
        
        .warning-box strong {{
            color: #dc3545;
        }}
        
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        pre {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            margin: 15px 0;
        }}
        
        pre code {{
            background: none;
            padding: 0;
            color: inherit;
        }}
        
        .endpoint-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }}
        
        .endpoint {{
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
        }}
        
        .endpoint.accessible {{
            border-left: 4px solid #28a745;
        }}
        
        .endpoint.not-accessible {{
            border-left: 4px solid #dc3545;
            opacity: 0.6;
        }}
        
        .endpoint.sensitive {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            
            .container {{
                box-shadow: none;
            }}
            
            .section {{
                page-break-inside: avoid;
            }}
        }}
        
        @media (max-width: 768px) {{
            .content {{
                padding: 20px;
            }}
            
            .info-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PROMETHEUS ATTACK SURFACE REPORT</h1>
            <div class="target">{results.get('target', 'Unknown Target')}</div>
            <div class="timestamp">Generated: {results.get('timestamp', 'Unknown')}</div>
        </div>
        
        <div class="content">
            {HTMLReport._generate_summary_section(results)}
            {HTMLReport._generate_security_highlights(results)}
            {HTMLReport._generate_targets_section(results)}
            {HTMLReport._generate_security_section(results)}
            {HTMLReport._generate_kubernetes_section(results)}
            {HTMLReport._generate_alerts_section(results)}
            {HTMLReport._generate_endpoints_section(results)}
            {HTMLReport._generate_recommendations_section(results)}
            {HTMLReport._generate_full_dumps_section(results)}
        </div>
    </div>
</body>
</html>"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f'[+] HTML report saved to: {output_path}')
    
    @staticmethod
    def _generate_summary_section(results):
        """Generate executive summary section."""
        prom_info = results.get('prometheus_info', {})
        targets = results.get('targets', {})
        perf = results.get('performance', {})
        security = results.get('security', {})
        
        html = '<div class="section">'
        html += '<h2 class="section-title">Executive Summary</h2>'
        html += '<div class="info-grid">'
        
        # Server info cards
        if prom_info.get('version'):
            html += f'<div class="info-card"><div class="label">Prometheus Version</div><div class="value">{prom_info["version"]}</div></div>'
        
        if prom_info.get('memory_bytes'):
            html += f'<div class="info-card"><div class="label">Memory Usage</div><div class="value">{format_bytes(prom_info["memory_bytes"])}</div></div>'
        
        if prom_info.get('tsdb_storage_size_bytes'):
            html += f'<div class="info-card"><div class="label">TSDB Size</div><div class="value">{format_bytes(prom_info["tsdb_storage_size_bytes"])}</div></div>'
        
        if prom_info.get('wal_size_bytes'):
            html += f'<div class="info-card"><div class="label">WAL Size</div><div class="value">{format_bytes(prom_info["wal_size_bytes"])}</div></div>'
        
        if targets:
            html += f'<div class="info-card"><div class="label">Active Targets</div><div class="value">{targets.get("total_active", 0)}</div></div>'
            html += f'<div class="info-card"><div class="label">Failed Targets</div><div class="value">{targets.get("health_status", {}).get("down", 0)}</div></div>'
        
        if perf.get('tsdb_head_series'):
            html += f'<div class="info-card"><div class="label">Head Series</div><div class="value">{perf["tsdb_head_series"]:,.0f}</div></div>'
        
        if perf.get('query_duration_99p'):
            html += f'<div class="info-card"><div class="label">Query Duration (p99)</div><div class="value">{perf["query_duration_99p"]:.3f}s</div></div>'
        
        html += '</div></div>'
        return html
    
    @staticmethod
    def _generate_security_highlights(results):
        """Generate critical security highlights only."""
        security = results.get('security', {})
        targets = results.get('targets', {})
        
        critical_findings = []
        if security.get('pprof_accessible'):
            critical_findings.append('<span class="badge badge-critical">CRITICAL</span> pprof Debug Endpoint Exposed')
        if security.get('web_enable_admin_api'):
            critical_findings.append('<span class="badge badge-critical">CRITICAL</span> Admin API Enabled')
        if security.get('config_accessible'):
            critical_findings.append('<span class="badge badge-high">HIGH</span> Config API Accessible')
        if security.get('federation_enabled'):
            critical_findings.append('<span class="badge badge-high">HIGH</span> Federation Enabled')
        if targets.get('health_status', {}).get('down', 0) > 0:
            critical_findings.append(f'<span class="badge badge-warning">WARN</span> {targets["health_status"]["down"]} Failed Targets')
        
        if not critical_findings:
            return ''
        
        html = '<div class="section">'
        html += '<h2 class="section-title">Security Highlights</h2>'
        html += '<ul class="findings-list">'
        for finding in critical_findings:
            html += f'<li class="finding-item">{finding}</li>'
        html += '</ul></div>'
        return html
    
    @staticmethod
    def _generate_targets_section(results):
        """Generate targets section."""
        targets = results.get('targets', {})
        if not targets:
            return ''
        
        html = '<div class="section">'
        html += '<h2 class="section-title">Target Enumeration</h2>'
        
        # Health status
        health = targets.get('health_status', {})
        if health:
            html += '<div class="subsection">'
            html += '<h3 class="subsection-title">Health Status</h3>'
            html += '<div class="info-grid">'
            for status, count in health.items():
                badge_class = 'badge-success' if status == 'up' else 'badge-critical' if status == 'down' else 'badge-warning'
                html += f'<div class="info-card"><div class="label">{status.upper()}</div><div class="value"><span class="badge {badge_class}">{count}</span></div></div>'
            html += '</div></div>'
        
        # Jobs
        jobs = targets.get('jobs', {})
        if jobs:
            html += '<div class="subsection">'
            html += '<h3 class="subsection-title">Scrape Jobs</h3>'
            html += '<table><thead><tr><th>Job Name</th><th>Target Count</th></tr></thead><tbody>'
            for job_name, job_targets in sorted(jobs.items()):
                html += f'<tr><td><code>{job_name}</code></td><td>{len(job_targets)}</td></tr>'
            html += '</tbody></table></div>'
        
        # Instances (collapsible)
        instances = targets.get('unique_instances', [])
        if instances:
            html += '<div class="subsection">'
            html += f'<details><summary>Target Instances ({len(instances)}) - Click to expand</summary>'
            html += '<div class="tip-box"><strong>TIP:</strong> These are the actual endpoints being monitored</div>'
            html += '<ul class="compact-list">'
            for instance in sorted(instances)[:100]:
                html += f'<li><code>{instance}</code></li>'
            if len(instances) > 100:
                html += f'<li><em>... and {len(instances) - 100} more</em></li>'
            html += '</ul></details></div>'
        
        html += '</div>'
        return html
    
    @staticmethod
    def _generate_security_section(results):
        """Generate security findings section."""
        security = results.get('security', {})
        
        html = '<div class="section">'
        html += '<h2 class="section-title">Security Findings</h2>'
        
        # Critical findings
        if security.get('pprof_accessible') or security.get('web_enable_admin_api'):
            html += '<div class="warning-box">'
            html += '<strong>CRITICAL:</strong> Security issues detected!'
            html += '<ul style="margin-top: 10px;">'
            if security.get('pprof_accessible'):
                html += '<li>pprof debug endpoint is exposed</li>'
            if security.get('web_enable_admin_api'):
                html += '<li>Admin API is enabled</li>'
            html += '</ul></div>'
        
        # Private IPs (collapsible)
        private_ips = security.get('private_ips', [])
        if private_ips:
            html += '<div class="subsection">'
            html += f'<details><summary>Internal IP Addresses ({len(private_ips)}) - Click to expand</summary>'
            html += '<div class="tip-box"><strong>TIP:</strong> These IPs reveal internal network topology</div>'
            html += '<ul class="compact-list">'
            for ip in private_ips[:100]:
                html += f'<li><code>{ip}</code></li>'
            if len(private_ips) > 100:
                html += f'<li><em>... and {len(private_ips) - 100} more</em></li>'
            html += '</ul></details></div>'
        
        # Hostnames (collapsible)
        hostnames = security.get('internal_hostnames', [])
        if hostnames:
            html += '<div class="subsection">'
            html += f'<details><summary>Internal Hostnames ({len(hostnames)}) - Click to expand</summary>'
            html += '<ul class="compact-list">'
            for hostname in hostnames[:100]:
                html += f'<li><code>{hostname}</code></li>'
            if len(hostnames) > 100:
                html += f'<li><em>... and {len(hostnames) - 100} more</em></li>'
            html += '</ul></details></div>'
        
        html += '</div>'
        return html
    
    @staticmethod
    def _generate_kubernetes_section(results):
        """Generate Kubernetes section."""
        sd = results.get('service_discovery', {})
        k8s = sd.get('kubernetes', {})
        
        if not k8s or k8s.get('namespace_count', 0) == 0:
            return ''
        
        html = '<div class="section">'
        html += '<h2 class="section-title">Kubernetes Discovery</h2>'
        html += '<div class="tip-box"><strong>TIP:</strong> Kubernetes metrics reveal full cluster topology</div>'
        
        # Namespaces
        namespaces = k8s.get('namespaces', [])
        if namespaces:
            html += '<div class="subsection">'
            html += f'<h3 class="subsection-title">Namespaces ({len(namespaces)})</h3>'
            html += '<ul class="compact-list">'
            for ns in namespaces:
                # Highlight sensitive namespaces
                marker = ' <span class="badge badge-warning">SENSITIVE</span>' if any(x in ns.lower() for x in ['kube-system', 'default', 'prod']) else ''
                html += f'<li><code>{ns}</code>{marker}</li>'
            html += '</ul></div>'
        
        # Nodes (collapsible)
        nodes = k8s.get('nodes', [])
        if nodes:
            html += '<div class="subsection">'
            html += f'<details><summary>Nodes ({len(nodes)}) - Click to expand</summary>'
            html += '<ul class="compact-list">'
            for node in nodes:
                html += f'<li><code>{node}</code></li>'
            html += '</ul></details></div>'
        
        html += '</div>'
        return html
    
    @staticmethod
    def _generate_alerts_section(results):
        """Generate alerts and rules section."""
        rules_alerts = results.get('rules_alerts', {})
        if not rules_alerts:
            return ''
        
        html = '<div class="section">'
        html += '<h2 class="section-title">Rules and Alerts</h2>'
        
        if rules_alerts.get('total_rules'):
            html += '<div class="info-grid">'
            html += f'<div class="info-card"><div class="label">Total Rules</div><div class="value">{rules_alerts["total_rules"]}</div></div>'
            html += f'<div class="info-card"><div class="label">Recording Rules</div><div class="value">{rules_alerts.get("recording_rules_count", 0)}</div></div>'
            html += f'<div class="info-card"><div class="label">Alerting Rules</div><div class="value">{rules_alerts.get("alerting_rules_count", 0)}</div></div>'
            html += '</div>'
        
        active_alerts = rules_alerts.get('active_alerts', [])
        if active_alerts:
            html += '<div class="subsection">'
            html += f'<h3 class="subsection-title">Active Alerts ({len(active_alerts)})</h3>'
            html += '<table><thead><tr><th>Alert Name</th><th>Severity</th><th>State</th></tr></thead><tbody>'
            for alert in active_alerts[:20]:
                labels = alert.get('labels', {})
                severity = labels.get('severity', 'none')
                badge_class = 'badge-critical' if severity == 'critical' else 'badge-warning' if severity == 'warning' else 'badge-info'
                html += f'<tr><td><code>{labels.get("alertname", "unknown")}</code></td><td><span class="badge {badge_class}">{severity}</span></td><td>{alert.get("state", "unknown")}</td></tr>'
            html += '</tbody></table></div>'
        
        html += '</div>'
        return html
    
    @staticmethod
    def _generate_endpoints_section(results):
        """Generate endpoints section."""
        endpoints = results.get('endpoints', {})
        if not endpoints:
            return ''
        
        accessible = [(ep, info) for ep, info in endpoints.items() if info.get('accessible')]
        not_accessible = [(ep, info) for ep, info in endpoints.items() if not info.get('accessible')]
        
        html = '<div class="section">'
        html += '<h2 class="section-title">Endpoint Discovery</h2>'
        
        if accessible:
            html += '<div class="subsection">'
            html += f'<h3 class="subsection-title">Accessible Endpoints ({len(accessible)})</h3>'
            html += '<div class="endpoint-list">'
            
            critical_endpoints = ['/debug/pprof/', '/config', '/api/v1/status/config']
            
            for endpoint, info in sorted(accessible):
                css_class = 'endpoint accessible'
                if endpoint in critical_endpoints:
                    css_class = 'endpoint accessible sensitive'
                html += f'<div class="{css_class}">{endpoint}</div>'
            
            html += '</div></div>'
        
        html += '</div>'
        return html
    
    @staticmethod
    def _generate_recommendations_section(results):
        """Generate recommendations section."""
        html = '<div class="section">'
        html += '<h2 class="section-title">Actionable Recommendations</h2>'
        
        security = results.get('security', {})
        targets = results.get('targets', {})
        
        # Critical recommendations
        if security.get('pprof_accessible'):
            html += '<div class="warning-box">'
            html += '<strong>CRITICAL:</strong> pprof Debug Endpoint Exposed<br>'
            html += '<strong>Impact:</strong> Memory dumps can leak sensitive data, credentials, and internal state<br>'
            html += '<strong>Action:</strong> Visit <code>/debug/pprof/heap</code> and <code>/debug/pprof/goroutine?debug=2</code> to dump memory'
            html += '</div>'
        
        if security.get('config_accessible'):
            html += '<div class="action-box">'
            html += '<strong>HIGH:</strong> Configuration API Accessible<br>'
            html += '<strong>Impact:</strong> Full config may contain credentials and sensitive paths<br>'
            html += '<strong>Action:</strong> Review <code>/api/v1/status/config</code> for: bearer_token, password, tls_config'
            html += '</div>'
        
        if targets and targets.get('health_status', {}).get('down', 0) > 0:
            html += '<div class="tip-box">'
            html += f'<strong>MEDIUM:</strong> {targets["health_status"]["down"]} Failed Scrape Targets<br>'
            html += '<strong>Impact:</strong> Failed targets may still reveal internal service URLs and endpoints<br>'
            html += '<strong>Action:</strong> Check <code>/api/v1/targets</code> for dropped/failed targets and their scrape URLs'
            html += '</div>'
        
        # General next steps
        html += '<div class="subsection">'
        html += '<h3 class="subsection-title">General Next Steps</h3>'
        html += '<pre><code>'
        html += '# Query interesting metrics\n'
        html += 'curl \'http://target:9090/api/v1/query?query=up\'\n'
        html += 'curl \'http://target:9090/api/v1/query?query=node_uname_info\'\n\n'
        html += '# Enumerate all targets\n'
        html += 'curl \'http://target:9090/api/v1/targets\' | jq .\n\n'
        html += '# Extract configuration\n'
        html += 'curl \'http://target:9090/api/v1/status/config\' | jq .\n\n'
        html += '# Download all metrics via federation\n'
        html += 'curl -G \'http://target:9090/federate\' --data-urlencode \'match[]={__name__!=""}\''
        html += '</code></pre>'
        html += '</div>'
        
        html += '</div>'
        return html


    @staticmethod
    def _generate_full_dumps_section(results):
        """Generate full data dumps section if available."""
        if not results.get('raw_config') and not results.get('raw_flags'):
            return ''
        
        html = '<div class="section">'
        html += '<h2 class="section-title">Full Data Dumps</h2>'
        html += '<div class="warning-box"><strong>WARNING:</strong> This section contains potentially sensitive information including configurations, credentials, and internal endpoints.</div>'
        
        # Config dump (collapsible)
        raw_config = results.get('raw_config', {})
        if raw_config and raw_config.get('yaml'):
            html += '<div class="subsection">'
            html += '<details><summary>Prometheus Configuration (YAML) - Click to expand</summary>'
            html += '<div class="warning-box"><strong>CAUTION:</strong> May contain bearer tokens, passwords, API keys, file paths</div>'
            yaml_config = raw_config["yaml"][:10000]  # Truncate very large configs
            if len(raw_config["yaml"]) > 10000:
                yaml_config += '\n\n... (truncated, config is too large)'
            html += f'<pre><code>{yaml_config}</code></pre>'
            html += '</details></div>'
        
        # Flags dump
        raw_flags = results.get('raw_flags', {})
        if raw_flags:
            html += '<div class="subsection">'
            html += '<h3 class="subsection-title">Command-Line Flags</h3>'
            html += '<table><thead><tr><th>Flag</th><th>Value</th></tr></thead><tbody>'
            for flag, value in sorted(raw_flags.items()):
                html += f'<tr><td><code>{flag}</code></td><td><code>{value}</code></td></tr>'
            html += '</tbody></table></div>'
        
        # Target details (collapsible)
        targets = results.get('targets', {})
        active_targets = targets.get('active_targets', [])
        if active_targets:
            html += '<div class="subsection">'
            html += f'<details><summary>Full Target Details ({len(active_targets)}) - Click to expand</summary>'
            html += '<div class="warning-box"><strong>CAUTION:</strong> Scrape URLs may contain credentials and bearer tokens</div>'
            html += '<table><thead><tr><th>Job</th><th>Instance</th><th>Scrape URL</th><th>Health</th></tr></thead><tbody>'
            for target in active_targets[:100]:
                labels = target.get('labels', {})
                scrape_url = target.get('scrapeUrl', 'N/A')
                health = target.get('health', 'unknown')
                badge_class = 'badge-success' if health == 'up' else 'badge-critical'
                html += f'<tr><td><code>{labels.get("job", "unknown")}</code></td><td><code>{labels.get("instance", "unknown")}</code></td><td><code>{scrape_url}</code></td><td><span class="badge {badge_class}">{health}</span></td></tr>'
            if len(active_targets) > 100:
                html += f'<tr><td colspan="4"><em>... and {len(active_targets) - 100} more targets (limit display to first 100)</em></td></tr>'
            html += '</tbody></table></details></div>'
        
        html += '</div>'
        return html


class OperatorReport:
    """Generate operator-friendly reports."""
    
    @staticmethod
    def print_banner():
        """Print tool banner."""
        print('=' * 80)
        print(' ' * 20 + 'PROMETHEUS ATTACK SURFACE ENUMERATOR')
        print('=' * 80)
        print()
    
    @staticmethod
    def print_security_tips():
        """Print security testing tips."""
        print('\n' + '=' * 80)
        print('SECURITY TESTING TIPS')
        print('=' * 80)
        print('''
[!] Key Things to Check:

[1] pprof Endpoint Exposed?
    => Visit /debug/pprof/ for heap dumps, goroutines, CPU profiles
    => Can leak memory contents, code paths, internal state
    => Try: /debug/pprof/heap, /debug/pprof/goroutine?debug=2

[2] Config API Accessible?
    => Visit /api/v1/status/config for full YAML config
    => May contain: bearer tokens, passwords, API keys, paths
    => Look for: basic_auth, bearer_token, tls_config, file_sd paths

[3] Federation Enabled?
    => Visit /federate?match[]={__name__!=""}
    => Can scrape ALL metrics from the server
    => Useful for exfiltrating complete metric data

[4] Failed Targets?
    => Check /api/v1/targets for down targets
    => Scrape URLs may reveal internal services, IPs, ports
    => Look for: authentication endpoints, databases, APIs

[5] Service Discovery Config?
    => kubernetes_sd: May reveal cluster structure, namespaces
    => consul_sd: May reveal Consul addresses and services
    => ec2_sd: May reveal AWS account IDs, regions, instance types
    => Check /service-discovery endpoint

[6] Alert Rules?
    => Visit /api/v1/rules
    => Rules often contain thresholds, service names, critical metrics
    => May reveal: service dependencies, infrastructure layout

[7] Labels & Series?
    => Query /api/v1/labels for all label names
    => Query /api/v1/label/<name>/values for label values
    => High-value labels: instance, job, namespace, pod, node, service

[8] PromQL Queries?
    => Try: up, node_uname_info, kube_node_info
    => Query for: {__name__!=""} (all metrics)
    => Look for: version info, hostnames, internal IPs

[9] Check for Sensitive Metrics?
    => Look for metrics containing: password, token, secret, key
    => Check labels for: connection strings, file paths, usernames

[10] Time Series Data?
     => Large TSDB/WAL sizes may indicate extensive historical data
     => Query ranges to see data retention period
     => Historical data may contain now-rotated credentials
''')
    
    @staticmethod
    def print_actionable_recommendations(results):
        """Print actionable next steps based on findings."""
        print('\n' + '=' * 80)
        print('ACTIONABLE RECOMMENDATIONS')
        print('=' * 80)
        
        target_url = results.get('target', 'http://target:9090')
        recommendations = []
        security = results.get('security', {})
        prom_info = results.get('prometheus_info', {})
        targets = results.get('targets', {})
        rules_alerts = results.get('rules_alerts', {})
        endpoints = results.get('endpoints', {})
        
        # Critical findings
        if security.get('pprof_accessible'):
            recommendations.append({
                'severity': 'CRITICAL',
                'finding': 'pprof Debug Endpoint Exposed',
                'impact': 'Memory dumps can leak sensitive data, credentials, and internal state',
                'action': f'Visit {target_url}/debug/pprof/heap and {target_url}/debug/pprof/goroutine?debug=2'
            })
        
        if security.get('web_enable_admin_api'):
            recommendations.append({
                'severity': 'CRITICAL',
                'finding': 'Admin API Enabled',
                'impact': 'Allows snapshot creation, TSDB management, metric deletion',
                'action': f'Test POST to {target_url}/-/reload and {target_url}/api/v1/admin/tsdb/snapshot'
            })
        
        # High findings
        if security.get('config_accessible'):
            recommendations.append({
                'severity': 'HIGH',
                'finding': 'Configuration API Accessible',
                'impact': 'Full config may contain credentials and sensitive paths',
                'action': f'Review {target_url}/api/v1/status/config for: bearer_token, password, tls_config'
            })
        
        if security.get('federation_enabled'):
            recommendations.append({
                'severity': 'HIGH',
                'finding': 'Federation Endpoint Enabled',
                'impact': 'Allows scraping all metrics from this Prometheus instance',
                'action': f'Query {target_url}/federate?match[]={{__name__!=""}} to export all metrics'
            })
        
        # Medium findings
        if targets and targets.get('health_status', {}).get('down', 0) > 0:
            recommendations.append({
                'severity': 'MEDIUM',
                'finding': f'{targets["health_status"]["down"]} Failed Scrape Targets',
                'impact': 'Failed targets may still reveal internal service URLs and endpoints',
                'action': f'Check {target_url}/api/v1/targets for dropped/failed targets and their scrape URLs'
            })
        
        if len(security.get('private_ips', [])) > 0:
            recommendations.append({
                'severity': 'MEDIUM',
                'finding': f'{len(security["private_ips"])} Internal IP Addresses Found',
                'impact': 'Reveals internal network topology and address ranges',
                'action': 'Map internal IPs to services and attempt lateral movement'
            })
        
        # Informational
        if rules_alerts and rules_alerts.get('total_rules', 0) > 0:
            recommendations.append({
                'severity': 'INFO',
                'finding': f'{rules_alerts["total_rules"]} Alert/Recording Rules',
                'impact': 'Rules reveal service names, thresholds, and monitoring coverage',
                'action': f'Review {target_url}/api/v1/rules for service discovery and infrastructure details'
            })
        
        # Kubernetes specific
        sd = results.get('service_discovery', {})
        k8s = sd.get('kubernetes', {})
        if k8s and k8s.get('namespace_count', 0) > 0:
            recommendations.append({
                'severity': 'HIGH',
                'finding': f'Kubernetes Cluster Discovered ({k8s["namespace_count"]} namespaces)',
                'impact': 'Full cluster topology including pods, nodes, and services exposed',
                'action': f'Query kube_* metrics: {target_url}/api/v1/query?query=kube_pod_info'
            })
        
        # Service discovery
        enabled_sd = sd.get('enabled_mechanisms', [])
        if 'kubernetes_sd_configs' in enabled_sd:
            recommendations.append({
                'severity': 'MEDIUM',
                'finding': 'Kubernetes Service Discovery Enabled',
                'impact': 'Config may contain Kubernetes API credentials and endpoints',
                'action': f'Check {target_url}/api/v1/status/config for kubernetes_sd_configs with bearer tokens'
            })
        
        if 'consul_sd_configs' in enabled_sd:
            recommendations.append({
                'severity': 'MEDIUM',
                'finding': 'Consul Service Discovery Enabled',
                'impact': 'Config may contain Consul addresses and authentication',
                'action': f'Check {target_url}/api/v1/status/config for consul_sd_configs and Consul ACL tokens'
            })
        
        if any(x in enabled_sd for x in ['ec2_sd_configs', 'azure_sd_configs', 'gce_sd_configs']):
            cloud_types = [x.replace('_sd_configs', '').upper() for x in enabled_sd if x in ['ec2_sd_configs', 'azure_sd_configs', 'gce_sd_configs']]
            recommendations.append({
                'severity': 'MEDIUM',
                'finding': f'Cloud Service Discovery: {", ".join(cloud_types)}',
                'impact': 'Config may contain cloud credentials and account information',
                'action': f'Check {target_url}/api/v1/status/config for cloud provider credentials and IAM roles'
            })
        
        # Print recommendations grouped by severity
        if recommendations:
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']
            
            for severity in severity_order:
                items = [r for r in recommendations if r['severity'] == severity]
                if not items:
                    continue
                
                print(f'\n[{severity}]')
                for rec in items:
                    print(f'\n  Finding: {rec["finding"]}')
                    print(f'  Impact:  {rec["impact"]}')
                    print(f'  Action:  {rec["action"]}')
        else:
            print('\n  No significant security findings detected.')
        
        # General next steps
        print('\n' + '-' * 80)
        print('GENERAL NEXT STEPS:')
        print('-' * 80)
        print(f'''
1. Query Interesting Metrics:
   curl '{target_url}/api/v1/query?query=up'
   curl '{target_url}/api/v1/query?query=node_uname_info'
   curl '{target_url}/api/v1/query?query={{__name__!=""}}'

2. Enumerate All Targets:
   curl '{target_url}/api/v1/targets' | jq .

3. Extract Configuration:
   curl '{target_url}/api/v1/status/config' | jq .

4. Download All Metrics via Federation:
   curl -G '{target_url}/federate' --data-urlencode 'match[]={{__name__!=""}}'

5. Enumerate Labels for Service Discovery:
   curl '{target_url}/api/v1/labels'
   curl '{target_url}/api/v1/label/instance/values'
   curl '{target_url}/api/v1/label/job/values'

6. Check for Kubernetes Metrics:
   curl '{target_url}/api/v1/query?query=kube_pod_info'
   curl '{target_url}/api/v1/query?query=kube_node_info'

7. Look for Database Exporters:
   curl '{target_url}/api/v1/query?query=pg_up'
   curl '{target_url}/api/v1/query?query=mysql_up'
   curl '{target_url}/api/v1/query?query=redis_up'
''')
    
    @staticmethod
    def print_summary(results):
        """Print executive summary."""
        print('\n' + '=' * 80)
        print('EXECUTIVE SUMMARY')
        print('=' * 80)
        
        target_url = results.get('target', '')
        prom_info = results.get('prometheus_info', {})
        targets = results.get('targets', {})
        security = results.get('security', {})
        perf = results.get('performance', {})
        
        # Server info
        print('\n[*] Prometheus Server Information:')
        if prom_info.get('version'):
            print(f'    Version: {prom_info["version"]}')
        if prom_info.get('go_version'):
            print(f'    Go Version: {prom_info["go_version"]}')
        if prom_info.get('memory_bytes'):
            mem_gb = prom_info["memory_bytes"] / (1024**3)
            marker = '[!]' if mem_gb > 4 else ''
            print(f'    Memory Usage: {format_bytes(prom_info["memory_bytes"])} {marker}')
        if prom_info.get('goroutines'):
            print(f'    Goroutines: {prom_info["goroutines"]}')
        if prom_info.get('open_fds'):
            print(f'    Open FDs: {prom_info["open_fds"]}')
        
        # TSDB stats
        print('\n[*] Time Series Database:')
        if prom_info.get('tsdb_storage_size_bytes'):
            print(f'    TSDB Size: {format_bytes(prom_info["tsdb_storage_size_bytes"])}')
        if prom_info.get('wal_size_bytes'):
            wal_gb = prom_info["wal_size_bytes"] / (1024**3)
            marker = '[!] (Large WAL!)' if wal_gb > 5 else ''
            print(f'    WAL Size: {format_bytes(prom_info["wal_size_bytes"])} {marker}')
        if perf.get('tsdb_head_series'):
            print(f'    Head Series: {perf["tsdb_head_series"]:,.0f}')
        if perf.get('tsdb_head_samples'):
            print(f'    Head Samples: {perf["tsdb_head_samples"]:,.0f}')
        
        # Targets
        print('\n[*] Scrape Targets:')
        if targets:
            print(f'    Active Targets: {targets.get("total_active", 0)}')
            failed = targets.get("health_status", {}).get("down", 0)
            marker = '[!]' if failed > 0 else ''
            print(f'    Failed Targets: {failed} {marker}')
            print(f'    Scrape Jobs: {len(targets.get("job_names", []))}')
        
        # Performance
        print('\n[*] Performance:')
        if perf.get('query_duration_99p'):
            p99 = perf["query_duration_99p"]
            marker = '[!] (Slow!)' if p99 > 1.0 else ''
            print(f'    Query Duration (p99): {p99:.3f}s {marker}')
        if perf.get('query_duration_50p'):
            print(f'    Query Duration (p50): {perf["query_duration_50p"]:.3f}s')
        if perf.get('scrape_pools'):
            print(f'    Scrape Pools: {perf["scrape_pools"]}')
        
        # Remote storage
        if perf.get('remote_write_enabled'):
            print('    Remote Write: ENABLED [i]')
        if perf.get('remote_read_enabled'):
            print('    Remote Read: ENABLED [i]')
        
        # Security findings
        print('\n[*] Security Findings:')
        issues_found = False
        
        if security.get('pprof_accessible'):
            print('    [!] pprof Debug Endpoint: EXPOSED')
            print(f'        {target_url}/debug/pprof/')
            issues_found = True
        if security.get('fgprof_accessible'):
            print('    [!] fgprof Debug Endpoint: EXPOSED')
            print(f'        {target_url}/debug/fgprof')
            issues_found = True
        if security.get('config_accessible'):
            print('    Config API: ACCESSIBLE')
            print(f'        {target_url}/api/v1/status/config')
        if security.get('federation_enabled'):
            print('    Federation: ENABLED')
            print(f'        {target_url}/federate')
        if security.get('web_enable_admin_api'):
            print('    [!] Admin API: ENABLED')
            issues_found = True
        if security.get('web_enable_lifecycle'):
            print('    [!] Lifecycle API: ENABLED')
            issues_found = True
        
        if not issues_found:
            print('    No critical security issues detected [OK]')
        
        # Service discovery
        sd = results.get('service_discovery', {})
        enabled_sd = sd.get('enabled_mechanisms', [])
        if enabled_sd:
            print('\n[*] Service Discovery:')
            for mechanism in enabled_sd:
                display_name = mechanism.replace('_sd_configs', '').replace('_', ' ').title()
                print(f'    - {display_name}')
    
    @staticmethod
    def print_targets(results):
        """Print target enumeration."""
        targets = results.get('targets', {})
        if not targets:
            return
        
        target_url = results.get('target', '')
        
        print('\n' + '=' * 80)
        print('TARGET ENUMERATION')
        print('=' * 80)
        print(f'[URL] {target_url}/targets')
        print(f'[API] {target_url}/api/v1/targets')
        
        print(f'\n[*] Total Active Targets: {targets.get("total_active", 0)}')
        print(f'[*] Total Dropped Targets: {targets.get("total_dropped", 0)}')
        
        # Health status
        health = targets.get('health_status', {})
        if health:
            print(f'\n[*] Health Status:')
            for status, count in health.items():
                marker = '[+]' if status == 'up' else '[!]' if status == 'down' else '[?]'
                print(f'    {marker} {status}: {count}')
            
            if health.get('down', 0) > 0:
                print(f'\n    [TIP] Failed targets still expose their scrape URLs!')
                print(f'    [ACTION] Check {target_url}/api/v1/targets for failed target URLs')
        
        # Jobs
        jobs = targets.get('jobs', {})
        if jobs:
            print(f'\n[*] Scrape Jobs ({len(jobs)}):')
            print('    [TIP] Job names often reveal service types (node-exporter, postgres, etc.)')
            for job_name, job_targets in sorted(jobs.items()):
                print(f'    - {job_name}: {len(job_targets)} targets')
        
        # Unique instances
        instances = targets.get('unique_instances', [])
        if instances:
            print(f'\n[*] Unique Target Instances ({len(instances)}):')
            print('    [TIP] These are the actual endpoints being monitored')
            for instance in sorted(instances)[:50]:  # Limit output
                print(f'    - {instance}')
            if len(instances) > 50:
                print(f'    ... and {len(instances) - 50} more')
    
    @staticmethod
    def print_kubernetes(results):
        """Print Kubernetes enumeration."""
        sd = results.get('service_discovery', {})
        k8s = sd.get('kubernetes', {})
        
        if not k8s or k8s.get('namespace_count', 0) == 0:
            return
        
        target_url = results.get('target', '')
        
        print('\n' + '=' * 80)
        print('KUBERNETES ENUMERATION')
        print('=' * 80)
        print('[TIP] Kubernetes metrics reveal full cluster topology')
        print(f'[ACTION] Query kube_pod_info, kube_node_info for detailed enumeration')
        print(f'[URL] {target_url}/api/v1/query?query=kube_pod_info')
        
        print(f'\n[*] Namespaces ({len(k8s.get("namespaces", []))}):')
        for ns in k8s.get('namespaces', []):
            # Highlight interesting namespaces
            interesting = ['kube-system', 'default', 'production', 'prod']
            marker = '[!]' if any(x in ns.lower() for x in interesting) else '   '
            print(f'    {marker} {ns}')
        
        print(f'\n[*] Nodes ({len(k8s.get("nodes", []))}):')
        for node in k8s.get('nodes', [])[:30]:
            print(f'    - {node}')
        if len(k8s.get('nodes', [])) > 30:
            print(f'    ... and {len(k8s.get("nodes", [])) - 30} more')
        
        print(f'\n[*] Services ({len(k8s.get("services", []))}):')
        for svc in k8s.get('services', [])[:30]:
            print(f'    - {svc}')
        if len(k8s.get('services', [])) > 30:
            print(f'    ... and {len(k8s.get("services", [])) - 30} more')
    
    @staticmethod
    def print_alerts_rules(results):
        """Print alerts and rules."""
        rules_alerts = results.get('rules_alerts', {})
        if not rules_alerts:
            return
        
        target_url = results.get('target', '')
        
        print('\n' + '=' * 80)
        print('RULES AND ALERTS')
        print('=' * 80)
        
        if rules_alerts.get('total_rules'):
            print(f'\n[*] Total Rules: {rules_alerts["total_rules"]}')
            print(f'    Recording Rules: {rules_alerts.get("recording_rules_count", 0)}')
            print(f'    Alerting Rules: {rules_alerts.get("alerting_rules_count", 0)}')
            print(f'\n    [TIP] Rules reveal service names, thresholds, and dependencies')
            print(f'    [ACTION] Review {target_url}/api/v1/rules for infrastructure details')
        
        active_alerts = rules_alerts.get('active_alerts', [])
        if active_alerts:
            print(f'\n[*] Active Alerts ({len(active_alerts)}):')
            print(f'    URL: {target_url}/alerts')
            print(f'    API: {target_url}/api/v1/alerts')
            print()
            for alert in active_alerts[:20]:
                labels = alert.get('labels', {})
                severity = labels.get('severity', 'none')
                marker = '[CRIT]' if severity == 'critical' else '[WARN]' if severity == 'warning' else '[INFO]'
                print(f'    {marker} {labels.get("alertname", "unknown")} '
                      f'[{severity}] '
                      f'({alert.get("state", "unknown")})')
            if len(active_alerts) > 20:
                print(f'    ... and {len(active_alerts) - 20} more')
        
        # Alertmanagers
        am_urls = rules_alerts.get('alertmanager_urls', [])
        if am_urls:
            print(f'\n[*] Alertmanagers ({len(am_urls)}):')
            print(f'    [TIP] Alertmanager URLs may be internal endpoints')
            for url in am_urls:
                print(f'    - {url}')
    
    @staticmethod
    def print_security_findings(results):
        """Print security findings."""
        security = results.get('security', {})
        target_url = results.get('target', '')
        
        print('\n' + '=' * 80)
        print('SECURITY FINDINGS')
        print('=' * 80)
        
        # Private IPs
        private_ips = security.get('private_ips', [])
        if private_ips:
            print(f'\n[*] Internal/Private IP Addresses ({len(private_ips)}):')
            print('    [TIP] These IPs reveal internal network topology')
            for ip in private_ips[:50]:
                print(f'    - {ip}')
            if len(private_ips) > 50:
                print(f'    ... and {len(private_ips) - 50} more')
        
        # Internal hostnames
        hostnames = security.get('internal_hostnames', [])
        if hostnames:
            print(f'\n[*] Internal Hostnames ({len(hostnames)}):')
            print('    [TIP] Internal DNS names often reveal service types and environments')
            for hostname in hostnames[:50]:
                print(f'    - {hostname}')
            if len(hostnames) > 50:
                print(f'    ... and {len(hostnames) - 50} more')
        
        # Sensitive findings
        sensitive = security.get('sensitive_findings', [])
        if sensitive:
            print(f'\n[*] Sensitive Keywords Found:')
            print('    [!!] WARNING: Config may contain credentials or secrets')
            print(f'    [URL] {target_url}/api/v1/status/config')
            for finding in sensitive:
                print(f'    [!] {finding}')
        
        # Debug endpoints
        print(f'\n[*] Debug Endpoints:')
        if security.get('pprof_accessible'):
            print(f'    pprof: EXPOSED [!]')
            print(f'           [URL] {target_url}/debug/pprof/')
            print(f'           [ACTION] Try these endpoints:')
            print(f'                    {target_url}/debug/pprof/heap')
            print(f'                    {target_url}/debug/pprof/goroutine?debug=2')
            print(f'                    {target_url}/debug/pprof/profile?seconds=30')
        else:
            print(f'    pprof: Not accessible')
        
        if security.get('fgprof_accessible'):
            print(f'    fgprof: EXPOSED [!]')
            print(f'            [URL] {target_url}/debug/fgprof')
        else:
            print(f'    fgprof: Not accessible')
    
    @staticmethod
    def print_interesting_labels(results):
        """Print interesting label values."""
        labels_series = results.get('labels_and_series', {})
        interesting = labels_series.get('interesting_labels', {})
        
        if not interesting:
            return
        
        target_url = results.get('target', '')
        
        print('\n' + '=' * 80)
        print('INTERESTING LABELS')
        print('=' * 80)
        print('[TIP] Labels reveal service structure - use these values in PromQL queries')
        print(f'[URL] {target_url}/api/v1/labels')
        
        for label_name, values in sorted(interesting.items()):
            if values:
                print(f'\n[*] {label_name} ({len(values)} values):')
                print(f'    [API] {target_url}/api/v1/label/{label_name}/values')
                for value in values[:30]:
                    print(f'    - {value}')
                if len(values) > 30:
                    print(f'    ... and {len(values) - 30} more')
    
    @staticmethod
    def print_endpoint_discovery(results):
        """Print endpoint discovery results."""
        endpoints = results.get('endpoints', {})
        if not endpoints:
            return
        
        target_url = results.get('target', '')
        
        print('\n' + '=' * 80)
        print('ENDPOINT DISCOVERY')
        print('=' * 80)
        
        accessible = [(ep, info) for ep, info in endpoints.items() if info.get('accessible')]
        not_accessible = [(ep, info) for ep, info in endpoints.items() if not info.get('accessible')]
        
        if accessible:
            print(f'\n[*] Accessible Endpoints ({len(accessible)}):')
            
            # Highlight critical endpoints
            critical_endpoints = ['/debug/pprof/', '/config', '/api/v1/status/config']
            
            for endpoint, info in sorted(accessible):
                marker = '[+]'
                suffix = ''
                if endpoint in critical_endpoints:
                    suffix = ' [!] SENSITIVE'
                full_url = f'{target_url}{endpoint}'
                print(f'    {marker} {endpoint}{suffix}')
                if endpoint in critical_endpoints:
                    print(f'        {full_url}')
        
        if not_accessible and len(not_accessible) < 30:
            print(f'\n[*] Not Accessible ({len(not_accessible)}):')
            for endpoint, info in sorted(not_accessible):
                status = info.get('status_code', 'ERROR')
                print(f'    [-] {endpoint} [{status}]')
    
    @staticmethod
    def print_top_findings(results):
        """Print top findings summary."""
        findings = results.get('interesting_findings', [])
        if not findings:
            return
        
        print('\n' + '=' * 80)
        print('TOP FINDINGS')
        print('=' * 80)
        print()
        
        for finding in findings:
            # Highlight critical findings
            if any(x in finding for x in ['pprof', 'Admin API', 'Exposed']):
                print(f'  * {finding}')
            else:
                print(f'  * {finding}')
    
    @staticmethod
    def print_complete_report(results):
        """Print complete operator-friendly report."""
        OperatorReport.print_banner()
        OperatorReport.print_top_findings(results)
        OperatorReport.print_summary(results)
        OperatorReport.print_targets(results)
        OperatorReport.print_kubernetes(results)
        OperatorReport.print_alerts_rules(results)
        OperatorReport.print_interesting_labels(results)
        OperatorReport.print_security_findings(results)
        OperatorReport.print_endpoint_discovery(results)
        OperatorReport.print_security_tips()
        OperatorReport.print_actionable_recommendations(results)
        print('\n' + '=' * 80)
        print('END OF REPORT')
        print('=' * 80 + '\n')
    
    @staticmethod
    def print_full_data_dumps(results):
        """Print full sensitive data dumps when --full-output is enabled."""
        print('\n' + '=' * 80)
        print('FULL SENSITIVE DATA DUMPS')
        print('=' * 80)
        print('[!] WARNING: This section contains potentially sensitive information!')
        print('=' * 80)
        
        # Configuration dump
        prom_info = results.get('prometheus_info', {})
        if 'config' in prom_info or results.get('raw_config'):
            print('\n' + '-' * 80)
            print('PROMETHEUS CONFIGURATION (YAML)')
            print('-' * 80)
            print('[!] This may contain: bearer tokens, passwords, API keys, file paths')
            print()
            
            config_data = results.get('raw_config', {})
            if config_data and config_data.get('yaml'):
                print(config_data['yaml'])
            else:
                print('[!] Config not available or failed to fetch')
        
        # Flags dump
        if results.get('raw_flags'):
            print('\n' + '-' * 80)
            print('PROMETHEUS COMMAND-LINE FLAGS')
            print('-' * 80)
            flags = results.get('raw_flags', {})
            for flag, value in sorted(flags.items()):
                print(f'  {flag}: {value}')
        
        # Full targets dump
        targets = results.get('targets', {})
        if targets.get('active_targets'):
            print('\n' + '-' * 80)
            print('ACTIVE TARGETS (FULL DETAILS)')
            print('-' * 80)
            print('[!] Scrape URLs may contain: credentials, bearer tokens, internal endpoints')
            print()
            
            for idx, target in enumerate(targets.get('active_targets', [])[:50], 1):
                labels = target.get('labels', {})
                scrape_url = target.get('scrapeUrl', 'N/A')
                health = target.get('health', 'unknown')
                last_error = target.get('lastError', '')
                
                print(f"Target #{idx}:")
                print(f"  Job: {labels.get('job', 'unknown')}")
                print(f"  Instance: {labels.get('instance', 'unknown')}")
                print(f"  Scrape URL: {scrape_url}")
                print(f"  Health: {health}")
                if last_error:
                    print(f"  Last Error: {last_error}")
                print(f"  Labels: {json.dumps(labels, indent=4)}")
                print()
        
        # Dropped targets (may reveal even more)
        if targets.get('dropped_targets'):
            print('\n' + '-' * 80)
            print('DROPPED TARGETS')
            print('-' * 80)
            print('[!] Dropped targets still expose discovered endpoints')
            print()
            
            for idx, target in enumerate(targets.get('dropped_targets', [])[:30], 1):
                discovered_labels = target.get('discoveredLabels', {})
                print(f"Dropped Target #{idx}:")
                print(f"  Discovered Labels: {json.dumps(discovered_labels, indent=4)}")
                print()
        
        # Full rules dump
        rules_alerts = results.get('rules_alerts', {})
        if rules_alerts.get('rules'):
            print('\n' + '-' * 80)
            print('ALERTING & RECORDING RULES')
            print('-' * 80)
            print('[!] Rules may reveal: service names, thresholds, PromQL queries')
            print()
            
            groups = rules_alerts.get('rules', {}).get('groups', [])
            for group in groups:
                print(f"Group: {group.get('name', 'unknown')}")
                print(f"  File: {group.get('file', 'unknown')}")
                print(f"  Interval: {group.get('interval', 'unknown')}")
                print()
                
                for rule in group.get('rules', []):
                    rule_type = rule.get('type', 'unknown')
                    print(f"  Rule Type: {rule_type}")
                    print(f"    Name: {rule.get('name', 'unknown')}")
                    print(f"    Query: {rule.get('query', 'N/A')}")
                    
                    if rule_type == 'alerting':
                        print(f"    For: {rule.get('duration', 'N/A')}")
                        print(f"    Labels: {json.dumps(rule.get('labels', {}))}")
                        print(f"    Annotations: {json.dumps(rule.get('annotations', {}))}")
                    
                    print()
        
        # Active alerts with full details
        if rules_alerts.get('active_alerts'):
            print('\n' + '-' * 80)
            print('ACTIVE ALERTS (FULL DETAILS)')
            print('-' * 80)
            
            for idx, alert in enumerate(rules_alerts.get('active_alerts', []), 1):
                print(f"Alert #{idx}:")
                print(f"  Labels: {json.dumps(alert.get('labels', {}), indent=4)}")
                print(f"  Annotations: {json.dumps(alert.get('annotations', {}), indent=4)}")
                print(f"  State: {alert.get('state', 'unknown')}")
                print(f"  Active At: {alert.get('activeAt', 'unknown')}")
                print(f"  Value: {alert.get('value', 'N/A')}")
                print()
        
        # Service discovery details
        sd = results.get('service_discovery', {})
        if sd.get('kubernetes'):
            k8s = sd['kubernetes']
            print('\n' + '-' * 80)
            print('KUBERNETES DISCOVERY DETAILS')
            print('-' * 80)
            print(f"Namespaces: {', '.join(k8s.get('namespaces', []))}")
            print(f"Pods: {len(k8s.get('pods', []))} total")
            print(f"Nodes: {', '.join(k8s.get('nodes', []))}")
            print(f"Services: {len(k8s.get('services', []))} total")
            print()
        
        # Alertmanager details
        if rules_alerts.get('alertmanagers'):
            print('\n' + '-' * 80)
            print('ALERTMANAGER CONFIGURATION')
            print('-' * 80)
            am_data = rules_alerts.get('alertmanagers', {})
            
            active_ams = am_data.get('activeAlertmanagers', [])
            if active_ams:
                print("Active Alertmanagers:")
                for am in active_ams:
                    print(f"  URL: {am.get('url')}")
                print()
            
            dropped_ams = am_data.get('droppedAlertmanagers', [])
            if dropped_ams:
                print("Dropped Alertmanagers:")
                for am in dropped_ams:
                    print(f"  URL: {am.get('url')}")
                print()
        
        # Label values (interesting ones)
        labels_series = results.get('labels_and_series', {})
        interesting_labels = labels_series.get('interesting_labels', {})
        
        if interesting_labels:
            print('\n' + '-' * 80)
            print('LABEL VALUES (FULL ENUMERATION)')
            print('-' * 80)
            print('[!] Labels reveal: endpoints, services, namespaces, pods, etc.')
            print()
            
            for label_name, values in sorted(interesting_labels.items()):
                if values:
                    print(f"{label_name} ({len(values)} values):")
                    for value in values:
                        print(f"  - {value}")
                    print()
        
        # Metadata dump
        if results.get('raw_metadata'):
            print('\n' + '-' * 80)
            print('METRIC METADATA')
            print('-' * 80)
            metadata = results.get('raw_metadata', {})
            for metric_name, metric_info in list(metadata.items())[:50]:
                print(f"{metric_name}:")
                print(f"  {json.dumps(metric_info, indent=4)}")
        
        print('\n' + '=' * 80)
        print('END OF SENSITIVE DATA DUMPS')
        print('=' * 80 + '\n')


class PrometheusMetricsParser:
    def __init__(self):
        self.metrics = defaultdict(list)
        self.help = {}
        self.types = {}
        self.bad_lines = []

    @staticmethod
    def unescape_label(value):
        return (
            value.replace(r'\\', '\\')
                 .replace(r'\n', '\n')
                 .replace(r'\"', '"')
        )

    def parse_labels(self, labels_raw):
        labels = {}
        if not labels_raw:
            return labels

        for match in LABEL_RE.finditer(labels_raw):
            key = match.group(1)
            value = self.unescape_label(match.group(2))
            labels[key] = value

        return labels

    @staticmethod
    def parse_value(value):
        if value in ('NaN', 'Inf', '+Inf', '-Inf'):
            return value
        try:
            if any(x in value for x in ['.', 'e', 'E']):
                return float(value)
            return int(value)
        except Exception:
            return value

    def parse(self, text):
        for line_number, line in enumerate(text.splitlines(), start=1):
            original_line = line
            line = line.strip()

            if not line:
                continue

            if line.startswith('# HELP'):
                parts = line.split(None, 3)
                if len(parts) == 4:
                    self.help[parts[2]] = parts[3]
                continue

            if line.startswith('# TYPE'):
                parts = line.split(None, 3)
                if len(parts) == 4:
                    self.types[parts[2]] = parts[3]
                continue

            if line.startswith('#'):
                continue

            match = METRIC_LINE_RE.match(line)
            if not match:
                self.bad_lines.append({'line_number': line_number, 'line': original_line})
                continue

            name = match.group('name')
            labels = self.parse_labels(match.group('labels'))
            value = self.parse_value(match.group('value'))
            timestamp = match.group('timestamp')

            self.metrics[name].append({
                'metric': name,
                'labels': labels,
                'value': value,
                'timestamp': timestamp,
                'type': self.types.get(name),
                'help': self.help.get(name)
            })

        return self.metrics


class Extractor:
    def __init__(self, metrics):
        self.metrics = metrics

    def m(self, name):
        return self.metrics.get(name, [])

    def any_metrics_starting(self, prefixes):
        out = {}
        for name, items in self.metrics.items():
            if any(name.startswith(prefix) for prefix in prefixes):
                out[name] = items
        return out

    @staticmethod
    def labels_only(items):
        return [x.get('labels', {}) for x in items]

    def first_labels(self, name):
        items = self.m(name)
        if not items:
            return None
        return items[0].get('labels', {})

    def extract_identity(self):
        return {
            'linux_uname': self.labels_only(self.m('node_uname_info')),
            'linux_os': self.labels_only(self.m('node_os_info')),
            'linux_dmi': self.labels_only(self.m('node_dmi_info')),
            'windows_os': self.labels_only(self.m('windows_os_info')),
            'windows_hostname': self.labels_only(self.m('windows_cs_hostname')),
            'windows_cs_info': self.labels_only(self.m('windows_cs_info')),
            'windows_product': self.labels_only(self.m('windows_os_product_info')),
            'go_info': self.labels_only(self.m('go_info')),
            'build_info': self.labels_only(self.m('prometheus_build_info')) + self.labels_only(self.m('build_info')),
        }

    def extract_cpu(self):
        return {
            'linux_cpu_info': self.labels_only(self.m('node_cpu_info')),
            'linux_cpu_seconds': self.m('node_cpu_seconds_total'),
            'linux_load': {
                'load1': self.m('node_load1'),
                'load5': self.m('node_load5'),
                'load15': self.m('node_load15'),
            },
            'windows_cpu_info': self.labels_only(self.m('windows_cpu_info')),
            'windows_cpu_time': self.m('windows_cpu_time_total'),
            'process_cpu': self.m('process_cpu_seconds_total'),
            'go_cpu_classes': self.m('go_cpu_classes_gc_total_cpu_seconds_total'),
        }

    def extract_memory(self):
        return {
            'linux_memory': self.any_metrics_starting([
                'node_memory_'
            ]),
            'windows_memory': self.any_metrics_starting([
                'windows_memory_'
            ]),
            'process_memory': self.any_metrics_starting([
                'process_resident_memory_',
                'process_virtual_memory_',
                'process_heap_',
            ]),
            'go_memory': self.any_metrics_starting([
                'go_memstats_',
                'go_memory_',
                'go_gc_',
            ]),
            'container_memory': self.any_metrics_starting([
                'container_memory_'
            ]),
        }

    def extract_disks_filesystems(self):
        return {
            'linux_filesystems': self.any_metrics_starting([
                'node_filesystem_'
            ]),
            'linux_disk': self.any_metrics_starting([
                'node_disk_'
            ]),
            'linux_md': self.any_metrics_starting([
                'node_md_'
            ]),
            'linux_bcache': self.any_metrics_starting([
                'node_bcache_'
            ]),
            'device_mapper': self.labels_only(self.m('node_disk_device_mapper_info')),
            'windows_logical_disk': self.any_metrics_starting([
                'windows_logical_disk_'
            ]),
            'windows_physical_disk': self.any_metrics_starting([
                'windows_physical_disk_'
            ]),
            'container_fs': self.any_metrics_starting([
                'container_fs_'
            ]),
        }

    def extract_network(self):
        return {
            'linux_network_info': self.labels_only(self.m('node_network_info')),
            'linux_network': self.any_metrics_starting([
                'node_network_'
            ]),
            'linux_route_info': self.labels_only(self.m('node_network_route_info')),
            'linux_netstat': self.any_metrics_starting([
                'node_netstat_'
            ]),
            'linux_sockstat': self.any_metrics_starting([
                'node_sockstat_'
            ]),
            'linux_nf_conntrack': self.any_metrics_starting([
                'node_nf_conntrack_'
            ]),
            'windows_network': self.any_metrics_starting([
                'windows_net_'
            ]),
            'container_network': self.any_metrics_starting([
                'container_network_'
            ]),
        }

    def extract_processes_services(self):
        active_systemd = []
        for item in self.m('node_systemd_unit_state'):
            if str(item.get('value')) == '1':
                active_systemd.append(item)

        windows_services = []
        for item in self.m('windows_service_info'):
            labels = item.get('labels', {})
            windows_services.append({
                'name': labels.get('name'),
                'display_name': labels.get('display_name'),
                'run_as': labels.get('run_as'),
                'process_id': labels.get('process_id'),
                'state': 'active' if labels.get('process_id') not in (None, '', '0') else 'inactive',
                'labels': labels,
            })

        return {
            'linux_processes': self.any_metrics_starting([
                'node_processes_',
                'node_procs_'
            ]),
            'systemd_active_units': active_systemd,
            'systemd_all': self.any_metrics_starting([
                'node_systemd_'
            ]),
            'windows_services': windows_services,
            'windows_process': self.any_metrics_starting([
                'windows_process_'
            ]),
            'process_exporter': self.any_metrics_starting([
                'namedprocess_',
                'process_'
            ]),
            'go_threads_goroutines': {
                'goroutines': self.m('go_goroutines'),
                'threads': self.m('go_threads'),
            }
        }

    def extract_security_state(self):
        return {
            'selinux_enabled': self.m('node_selinux_enabled'),
            'entropy': self.m('node_entropy_available_bits'),
            'time': {
                'linux_time': self.m('node_time_seconds'),
                'linux_boot_time': self.m('node_boot_time_seconds'),
                'linux_timezone': self.labels_only(self.m('node_time_zone_offset_seconds')),
                'windows_timezone': self.labels_only(self.m('windows_os_timezone')),
            },
            'textfile_collector': self.any_metrics_starting([
                'node_textfile_'
            ]),
            'exporter_health': {
                'up': self.m('up'),
                'scrape_duration_seconds': self.m('scrape_duration_seconds'),
                'scrape_samples_scraped': self.m('scrape_samples_scraped'),
                'scrape_samples_post_metric_relabeling': self.m('scrape_samples_post_metric_relabeling'),
            }
        }

    def extract_docker_container(self):
        return {
            'container_info': self.labels_only(self.m('container_info')),
            'container_spec': self.any_metrics_starting([
                'container_spec_'
            ]),
            'container_cpu': self.any_metrics_starting([
                'container_cpu_'
            ]),
            'container_memory': self.any_metrics_starting([
                'container_memory_'
            ]),
            'container_fs': self.any_metrics_starting([
                'container_fs_'
            ]),
            'container_network': self.any_metrics_starting([
                'container_network_'
            ]),
            'container_tasks': self.any_metrics_starting([
                'container_tasks_'
            ]),
            'docker': self.any_metrics_starting([
                'engine_daemon_',
                'docker_'
            ]),
        }

    def extract_kubernetes(self):
        return {
            'kube_node': self.any_metrics_starting([
                'kube_node_'
            ]),
            'kube_pod': self.any_metrics_starting([
                'kube_pod_'
            ]),
            'kube_deployment': self.any_metrics_starting([
                'kube_deployment_'
            ]),
            'kube_replicaset': self.any_metrics_starting([
                'kube_replicaset_'
            ]),
            'kube_daemonset': self.any_metrics_starting([
                'kube_daemonset_'
            ]),
            'kube_statefulset': self.any_metrics_starting([
                'kube_statefulset_'
            ]),
            'kube_job': self.any_metrics_starting([
                'kube_job_'
            ]),
            'kube_cronjob': self.any_metrics_starting([
                'kube_cronjob_'
            ]),
            'kube_namespace': self.any_metrics_starting([
                'kube_namespace_'
            ]),
            'kube_service': self.any_metrics_starting([
                'kube_service_'
            ]),
            'kube_endpoint': self.any_metrics_starting([
                'kube_endpoint_'
            ]),
            'kube_secret': self.any_metrics_starting([
                'kube_secret_'
            ]),
            'kube_configmap': self.any_metrics_starting([
                'kube_configmap_'
            ]),
            'kube_persistentvolume': self.any_metrics_starting([
                'kube_persistentvolume_'
            ]),
            'kube_persistentvolumeclaim': self.any_metrics_starting([
                'kube_persistentvolumeclaim_'
            ]),
            'kube_role': self.any_metrics_starting([
                'kube_role_'
            ]),
            'kube_clusterrole': self.any_metrics_starting([
                'kube_clusterrole_'
            ]),
            'kube_serviceaccount': self.any_metrics_starting([
                'kube_serviceaccount_'
            ]),
        }

    def extract_databases_and_apps(self):
        prefixes = [
            'mysql_', 'mariadb_', 'postgres_', 'pg_', 'mongodb_', 'redis_', 'mssql_',
            'nginx_', 'apache_', 'http_', 'traefik_', 'haproxy_', 'envoy_',
            'rabbitmq_', 'kafka_', 'elasticsearch_', 'opensearch_', 'solr_',
            'jvm_', 'dotnet_', 'aspnetcore_', 'nodejs_', 'python_', 'gunicorn_',
            'celery_', 'sidekiq_', 'phpfpm_', 'php_', 'iis_', 'w3svc_',
            'aws_', 'azure_', 'gcp_', 'cloudwatch_',
        ]
        return self.any_metrics_starting(prefixes)

    def extract_internal_ips(self):
        found = set()
        all_text_parts = []

        for metric_name, items in self.metrics.items():
            all_text_parts.append(metric_name)
            for item in items:
                all_text_parts.append(str(item.get('value', '')))
                for k, v in item.get('labels', {}).items():
                    all_text_parts.append(k)
                    all_text_parts.append(str(v))

        blob = '\n'.join(all_text_parts)
        for ip in PRIVATE_IPV4_RE.findall(blob):
            found.add(ip)

        return sorted(found)

    def extract_sensitive_label_hits(self):
        hits = []

        for metric_name, items in self.metrics.items():
            metric_l = metric_name.lower()
            for item in items:
                labels = item.get('labels', {})
                value = item.get('value')

                haystacks = [metric_l]
                for k, v in labels.items():
                    haystacks.append(str(k).lower())
                    haystacks.append(str(v).lower())

                if any(word in h for word in SENSITIVE_WORDS for h in haystacks):
                    hits.append({
                        'metric': metric_name,
                        'labels': labels,
                        'value': value,
                    })

        return hits

    def extract_recon_summary(self):
        metric_names = sorted(self.metrics.keys())
        exporters_detected = []

        prefix_map = {
            'linux_node_exporter': 'node_',
            'windows_exporter': 'windows_',
            'kubernetes_kube_state_metrics': 'kube_',
            'cadvisor_container': 'container_',
            'go_runtime': 'go_',
            'process_exporter': 'process_',
            'named_process_exporter': 'namedprocess_',
            'nginx': 'nginx_',
            'apache': 'apache_',
            'postgres': 'postgres_',
            'mysql': 'mysql_',
            'redis': 'redis_',
            'mongodb': 'mongodb_',
            'rabbitmq': 'rabbitmq_',
            'jvm': 'jvm_',
            'dotnet': 'dotnet_',
        }

        for exporter, prefix in prefix_map.items():
            if any(name.startswith(prefix) for name in metric_names):
                exporters_detected.append(exporter)

        return {
            'total_metric_families': len(metric_names),
            'total_metric_samples': sum(len(v) for v in self.metrics.values()),
            'exporters_detected': exporters_detected,
            'metric_families': metric_names,
            'internal_private_ipv4s': self.extract_internal_ips(),
            'sensitive_label_hits_count': len(self.extract_sensitive_label_hits()),
        }

    def extract_interesting_findings(self):
        findings = {
            'summary': self.extract_recon_summary(),
            'identity': self.extract_identity(),
            'private_ips': self.extract_internal_ips(),
            'sensitive_label_hits': self.extract_sensitive_label_hits(),
            'routes': self.labels_only(self.m('node_network_route_info')),
            'network_interfaces': self.labels_only(self.m('node_network_info')),
            'mounted_filesystems': self.labels_only(self.m('node_filesystem_avail_bytes')) + self.labels_only(self.m('node_filesystem_avail')),
            'windows_services': self.extract_processes_services().get('windows_services'),
            'systemd_active_units': self.extract_processes_services().get('systemd_active_units'),
            'kubernetes_high_value': {
                'namespaces': self.labels_only(self.m('kube_namespace_created')) + self.labels_only(self.m('kube_namespace_labels')),
                'pods': self.labels_only(self.m('kube_pod_info')),
                'services': self.labels_only(self.m('kube_service_info')),
                'service_accounts': self.labels_only(self.m('kube_serviceaccount_info')),
                'secrets': self.labels_only(self.m('kube_secret_info')),
                'nodes': self.labels_only(self.m('kube_node_info')),
            },
            'containers': self.labels_only(self.m('container_info')),
            'security_state': self.extract_security_state(),
        }
        return findings

    def full_extract(self):
        return {
            'recon_summary': self.extract_recon_summary(),
            'identity': self.extract_identity(),
            'cpu': self.extract_cpu(),
            'memory': self.extract_memory(),
            'disks_filesystems': self.extract_disks_filesystems(),
            'network': self.extract_network(),
            'processes_services': self.extract_processes_services(),
            'security_state': self.extract_security_state(),
            'docker_container': self.extract_docker_container(),
            'kubernetes': self.extract_kubernetes(),
            'databases_and_apps': self.extract_databases_and_apps(),
            'interesting_findings': self.extract_interesting_findings(),
        }


class Output:
    @staticmethod
    def save_json(data, path):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f'[+] JSON written: {path}')

    @staticmethod
    def save_flat_csv(metrics, path):
        rows = []
        fields = set(['metric', 'value', 'timestamp', 'type', 'help'])

        for metric_name, items in metrics.items():
            for item in items:
                row = {
                    'metric': metric_name,
                    'value': item.get('value'),
                    'timestamp': item.get('timestamp'),
                    'type': item.get('type'),
                    'help': item.get('help'),
                }
                for k, v in item.get('labels', {}).items():
                    lk = f'label_{k}'
                    row[lk] = v
                    fields.add(lk)
                rows.append(row)

        fields = sorted(fields)

        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

        print(f'[+] CSV written: {path}')

    @staticmethod
    def print_section(title, data):
        print('\n' + '=' * 80)
        print(title)
        print('=' * 80)
        print(json.dumps(data, indent=2, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser(
        description='Prometheus Attack Surface Enumerator - Comprehensive reconnaissance tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Full enumeration of Prometheus server
  %(prog)s --url http://10.0.2.30:9090
  
  # With authentication
  %(prog)s --url http://prometheus:9090 --header "Authorization: Bearer TOKEN"
  
  # Dump all sensitive data (configs, targets, rules)
  %(prog)s --url http://prometheus:9090 --full-output
  
  # Analyze metrics from file
  %(prog)s --file metrics.txt
  
  # Query specific PromQL
  %(prog)s --url http://prometheus:9090 --query "up"
  
  # Save reports in multiple formats
  %(prog)s --url http://prometheus:9090 --json report.json --html report.html
  
  # Full dump saved to files
  %(prog)s --url http://prometheus:9090 --full-output --json full_dump.json --html report.html
        '''
    )
    
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--url', help='Prometheus server URL (e.g., http://host:9090)')
    src.add_argument('--file', help='Metrics file to analyze')
    
    ap.add_argument('--json', help='Save full report to JSON file')
    ap.add_argument('--html', help='Save report as HTML file with CSS styling')
    ap.add_argument('--raw-json', help='Save raw parsed metrics to JSON')
    ap.add_argument('--csv', help='Save flat metric samples to CSV')
    ap.add_argument('--query', help='Execute PromQL query (requires --url)')
    ap.add_argument('--full-output', action='store_true', help='Dump full sensitive data (configs, targets, rules, etc.)')
    ap.add_argument('--metrics-only', action='store_true', help='Only parse /metrics endpoint (skip API enumeration)')
    ap.add_argument('--no-report', action='store_true', help='Skip printing report (use with --json)')
    ap.add_argument('--timeout', type=int, default=15, help='HTTP timeout in seconds (default: 15)')
    ap.add_argument('--header', action='append', default=[], help='HTTP header (format: "Name: Value")')
    
    args = ap.parse_args()
    
    # Parse headers
    headers = {}
    for header in args.header:
        if ':' in header:
            k, v = header.split(':', 1)
            headers[k.strip()] = v.strip()
    
    # Initialize
    parser = None
    api_client = None
    metrics_text = None
    
    try:
        # Fetch or read metrics
        if args.url:
            # Determine base URL (remove /metrics if present)
            base_url = args.url.rstrip('/')
            if base_url.endswith('/metrics'):
                base_url = base_url[:-8]
            
            print(f'[+] Target: {base_url}')
            
            # Initialize API client
            api_client = PrometheusAPIClient(base_url, timeout=args.timeout, headers=headers)
            
            # Handle PromQL query
            if args.query:
                print(f'[+] Executing query: {args.query}')
                result = api_client.query(args.query)
                if result:
                    print('\n' + '=' * 80)
                    print('QUERY RESULTS')
                    print('=' * 80)
                    print(json.dumps(result, indent=2))
                else:
                    print('[!] Query failed or returned no results')
                return
            
            # Fetch metrics
            print(f'[+] Fetching metrics from {base_url}/metrics')
            metrics_result = api_client._get('/metrics')
            if not metrics_result['success']:
                print(f'[!] Failed to fetch metrics: {metrics_result.get("error", "Unknown error")}')
                sys.exit(1)
            
            metrics_text = metrics_result['content']
            
        else:
            print(f'[+] Reading metrics from file: {args.file}')
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                metrics_text = f.read()
        
        # Parse metrics
        print('[+] Parsing metrics...')
        parser = PrometheusMetricsParser()
        metrics = parser.parse(metrics_text)
        print(f'[+] Parsed {len(metrics)} metric families')
        
        if parser.bad_lines:
            print(f'[!] Skipped {len(parser.bad_lines)} malformed lines')
        
        # Create extractor for backwards compatibility
        extractor = Extractor(metrics)
        
        # Perform comprehensive enumeration if we have API access
        full_results = None
        if api_client and not args.metrics_only:
            enumerator = PrometheusEnumerator(api_client, parser)
            full_results = enumerator.enumerate_all()
        else:
            # Metrics-only analysis
            print('[+] Performing metrics-only analysis...')
            full_results = {
                'timestamp': datetime.now().isoformat(),
                'target': args.file if args.file else args.url,
                'metrics_analysis': extractor.extract_interesting_findings(),
            }
        
        # Print report
        if not args.no_report:
            if api_client and not args.metrics_only:
                OperatorReport.print_complete_report(full_results)
                
                # Print full sensitive data dumps if requested
                if args.full_output:
                    OperatorReport.print_full_data_dumps(full_results)
            else:
                # Print simple metrics analysis
                print('\n' + '=' * 80)
                print('METRICS ANALYSIS')
                print('=' * 80)
                metrics_analysis = full_results.get('metrics_analysis', {})
                summary = metrics_analysis.get('summary', {})
                
                print(f'\nTotal Metric Families: {summary.get("total_metric_families", 0)}')
                print(f'Total Samples: {summary.get("total_metric_samples", 0)}')
                print(f'Exporters Detected: {", ".join(summary.get("exporters_detected", []))}')
                
                private_ips = metrics_analysis.get('private_ips', [])
                if private_ips:
                    print(f'\nPrivate IPs Found ({len(private_ips)}):')
                    for ip in private_ips[:30]:
                        print(f'  - {ip}')
                    if len(private_ips) > 30:
                        print(f'  ... and {len(private_ips) - 30} more')
        
        # Save outputs
        if args.json:
            print(f'\n[+] Saving full report to {args.json}')
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump(full_results, f, indent=2, ensure_ascii=False, default=str)
        
        if args.html:
            print(f'\n[+] Generating HTML report: {args.html}')
            HTMLReport.generate(full_results, args.html)
        
        if args.raw_json:
            print(f'[+] Saving raw metrics to {args.raw_json}')
            with open(args.raw_json, 'w', encoding='utf-8') as f:
                json.dump(metrics, f, indent=2, ensure_ascii=False, default=str)
        
        if args.csv:
            print(f'[+] Saving metrics to CSV: {args.csv}')
            Output.save_flat_csv(metrics, args.csv)
        
        print('\n[+] Enumeration complete!')
        
    except KeyboardInterrupt:
        print('\n[!] Interrupted by user')
        sys.exit(130)
    except Exception as e:
        print(f'\n[!] Error: {e}')
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
