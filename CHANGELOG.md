# CHANGELOG

## [2.0.0] - 2026-06-23 - Industry-Grade Hardening Upgrade
### Added
- **Structured Logging (`app_logger.py`)**: Centralized rotating JSON/text logs, replacing unstructured `print()` statements.
- **Pydantic Configuration (`config.py`)**: Strict schema validation, bounds checking, and fallback mechanisms.
- **SQLite WAL State Manager (`state_manager.py`)**: Thread-safe persistent tracking of blocked IPs and SOC metrics via connection pooling and Write-Ahead Logging.
- **Atomic Log Writes (`logger.py`)**: Safe sidecar pattern implementation for CSV logging without data loss or truncation risks.
- **Prometheus Metrics**: `GET /api/metrics` added to dashboard for SOC observability.
- **Health Probes**: `GET /api/health` added to dashboard for load balancers.
- **Threat Distribution Chart**: Added Chart.js doughnut chart to dashboard.
- **HTML Reporting (`report_generator.py`)**: High-quality SOC reports mapping to MITRE ATT&CK.
- **Docker Support**: Containerization ready with `Dockerfile`.
- **Test Suite**: Introduced unit testing with `pytest`.

### Changed
- **Monitor Orchestration (`monitor.py`)**: Upgraded to use `ThreadPoolExecutor` with controlled queue size, bounded workers, and structured shutdown hooks.
- **Flow Tracking (`packet_features.py`)**: Introduced automatic memory expiration of stale flows via a dedicated background cleanup thread.
- **DPI and ML Analysis (`analyzer.py`)**: MITRE ATT&CK framework mappings implemented.

### Security
- **Data Cleaner (`data_cleaner.py`)**: Verified completely non-destructive (uses non-mutating `_cleaned.csv` pattern).
- **Dashboard API**: Added rate-limiting, CSP headers, and CSRF strict cookie attributes.
