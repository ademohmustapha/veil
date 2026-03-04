"""
AURORA Integration Manager
Real connectors to Splunk, Elastic SIEM, Wazuh, MISP, and file-based sources.
Each connector makes genuine authenticated API calls when credentials are configured.

Configure via ~/.aurora/integrations.json:
  {
    "splunk":  {"url": "https://splunk.corp:8089", "token": "${AURORA_SPLUNK_TOKEN}"},
    "elastic": {"url": "https://elastic.corp:9200", "api_key": "${AURORA_ELASTIC_API_KEY}"},
    "wazuh":   {"url": "https://wazuh.corp:55000", "username": "aurora-ro", "password": "${AURORA_WAZUH_PASS}"},
    "misp":    {"url": "https://misp.corp", "api_key": "${AURORA_MISP_KEY}"},
    "files":   [
      {"type": "json", "path": "/opt/scans/kryphorix-latest.json"},
      {"type": "csv",  "path": "/opt/imports/manual.csv"},
      {"type": "cef",  "path": "/var/log/siem/alerts.cef"}
    ]
  }
"""
from __future__ import annotations
import csv, json, logging, os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.paths import AURORA_HOME as _AURORA_HOME

logger = logging.getLogger("aurora.integrations")
_CONFIG_FILE = _AURORA_HOME / "integrations.json"

_SEV_MAP = {
    "critical": "critical", "crit": "critical", "1": "critical",
    "high": "high", "error": "high", "2": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium", "3": "medium",
    "low": "low", "4": "low",
    "info": "info", "informational": "info", "5": "info",
}

def _norm_sev(raw: str) -> str:
    return _SEV_MAP.get(str(raw).lower().strip(), "medium")

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _load_config() -> Dict:
    try:
        if _CONFIG_FILE.exists():
            return json.loads(_CONFIG_FILE.read_text())
    except Exception as e:
        logger.warning(f"Could not read integrations config: {e}")
    return {}

def _resolve(val: str) -> str:
    """Expand ${ENV_VAR} references in config values."""
    if isinstance(val, str) and val.startswith("${") and val.endswith("}"):
        key = val[2:-1]
        resolved = os.environ.get(key, "")
        if not resolved:
            logger.warning(f"Environment variable {key} is not set")
        return resolved
    return val or ""


def fetch_splunk(url: str, token: str, query: str = None,
                 max_results: int = 500, verify_ssl: bool = True) -> List[Dict]:
    """Pull notable events from Splunk via REST API."""
    try:
        import requests
    except ImportError:
        logger.error("requests not installed; run: pip install requests")
        return []
    if not query:
        query = (f'search index=notable | fields severity,rule_name,dest,'
                 f'description,mitre_tactic | head {max_results}')
    findings = []
    try:
        r = requests.post(
            f"{url}/services/search/jobs",
            data={"search": query, "output_mode": "json",
                  "exec_mode": "oneshot", "count": max_results},
            headers={"Authorization": f"Bearer {token}"},
            verify=verify_ssl, timeout=30)
        r.raise_for_status()
        for row in r.json().get("results", []):
            findings.append({
                "title":       row.get("rule_name", "Splunk Alert"),
                "severity":    _norm_sev(row.get("severity", row.get("urgency", "medium"))),
                "category":    row.get("mitre_tactic", "siem"),
                "source":      f"splunk:{url}",
                "description": row.get("description", ""),
                "target":      row.get("dest", ""),
                "ts":          row.get("_time", _now()),
                "raw":         row,
            })
        logger.info(f"Splunk: loaded {len(findings)} notable events")
    except Exception as e:
        logger.error(f"Splunk fetch failed: {e}")
    return findings


def fetch_elastic(url: str, api_key: str, index: str = ".siem-signals-*",
                  max_results: int = 500, verify_ssl: bool = True) -> List[Dict]:
    """Pull open SIEM signals from Elasticsearch."""
    try:
        import requests
    except ImportError:
        logger.error("requests not installed; run: pip install requests")
        return []
    findings = []
    try:
        r = requests.post(
            f"{url}/{index}/_search",
            json={"size": max_results,
                  "sort": [{"@timestamp": {"order": "desc"}}],
                  "query": {"term": {"signal.status": "open"}}},
            headers={"Authorization": f"ApiKey {api_key}",
                     "Content-Type": "application/json"},
            verify=verify_ssl, timeout=30)
        r.raise_for_status()
        for hit in r.json().get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            sig = src.get("signal", {})
            rule = sig.get("rule", {})
            findings.append({
                "title":       rule.get("name", "Elastic SIEM Alert"),
                "severity":    _norm_sev(sig.get("severity", "medium")),
                "category":    (rule.get("tags") or ["siem"])[0],
                "source":      f"elastic:{url}",
                "description": rule.get("description", ""),
                "target":      src.get("host", {}).get("name", ""),
                "ts":          src.get("@timestamp", _now()),
                "raw":         src,
            })
        logger.info(f"Elastic SIEM: loaded {len(findings)} signals")
    except Exception as e:
        logger.error(f"Elastic fetch failed: {e}")
    return findings


def fetch_wazuh(url: str, username: str, password: str,
                max_results: int = 500, verify_ssl: bool = True) -> List[Dict]:
    """Pull active alerts from Wazuh Manager REST API."""
    try:
        import requests
    except ImportError:
        logger.error("requests not installed; run: pip install requests")
        return []
    findings = []
    try:
        auth = requests.post(
            f"{url}/security/user/authenticate",
            auth=(username, password), verify=verify_ssl, timeout=10)
        auth.raise_for_status()
        token = auth.json()["data"]["token"]
        r = requests.get(
            f"{url}/alerts",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": max_results, "sort": "-timestamp",
                    "select": "rule.description,rule.level,rule.id,rule.mitre,agent.name,timestamp"},
            verify=verify_ssl, timeout=30)
        r.raise_for_status()
        for alert in r.json().get("data", {}).get("affected_items", []):
            rule = alert.get("rule", {})
            lvl = int(rule.get("level", 5))
            sev = ("critical" if lvl >= 12 else "high" if lvl >= 8
                   else "medium" if lvl >= 5 else "low")
            findings.append({
                "title":       rule.get("description", f"Wazuh Alert {rule.get('id', '')}"),
                "severity":    sev,
                "category":    (rule.get("mitre", {}).get("tactic") or ["siem"])[0]
                               if rule.get("mitre") else "siem",
                "source":      f"wazuh:{url}",
                "description": rule.get("description", ""),
                "target":      alert.get("agent", {}).get("name", ""),
                "ts":          alert.get("timestamp", _now()),
                "raw":         alert,
            })
        logger.info(f"Wazuh: loaded {len(findings)} alerts")
    except Exception as e:
        logger.error(f"Wazuh fetch failed: {e}")
    return findings


def fetch_misp(url: str, api_key: str, threat_level: int = 2,
               max_events: int = 100, verify_ssl: bool = True) -> List[Dict]:
    """Pull threat intelligence events from MISP."""
    try:
        import requests
    except ImportError:
        logger.error("requests not installed; run: pip install requests")
        return []
    lvl_map = {1: "high", 2: "medium", 3: "low", 4: "info"}
    findings = []
    try:
        r = requests.post(
            f"{url}/events/restSearch",
            json={"returnFormat": "json", "threat_level_id": threat_level,
                  "limit": max_events, "published": True},
            headers={"Authorization": api_key, "Accept": "application/json",
                     "Content-Type": "application/json"},
            verify=verify_ssl, timeout=30)
        r.raise_for_status()
        for wrap in r.json().get("response", []):
            ev = wrap.get("Event", wrap)
            findings.append({
                "title":       ev.get("info", "MISP Threat Event"),
                "severity":    lvl_map.get(int(ev.get("threat_level_id", 2)), "medium"),
                "category":    "threat_intelligence",
                "source":      f"misp:{url}",
                "description": ev.get("info", ""),
                "target":      "",
                "ts":          ev.get("timestamp", _now()),
                "raw":         ev,
            })
        logger.info(f"MISP: loaded {len(findings)} threat events")
    except Exception as e:
        logger.error(f"MISP fetch failed: {e}")
    return findings


def fetch_json_file(path: str) -> List[Dict]:
    """Import findings from a JSON file (Kryphorix reports, generic arrays, etc.)."""
    findings = []
    try:
        data = json.loads(Path(path).read_text())
        items = (data if isinstance(data, list)
                 else data.get("findings", data.get("results", [data])))
        for item in items:
            if not isinstance(item, dict):
                continue
            findings.append({
                "title":       item.get("title", item.get("name", item.get("alert", "Finding"))),
                "severity":    _norm_sev(item.get("severity", item.get("risk", "medium"))),
                "category":    item.get("category", item.get("module", "general")),
                "source":      f"json:{Path(path).name}",
                "description": item.get("description", item.get("details", "")),
                "target":      item.get("target", item.get("host", item.get("url", ""))),
                "cve":         item.get("cve", ""),
                "cvss":        float(item.get("cvss", 0) or 0),
                "ts":          item.get("timestamp", _now()),
                "raw":         item,
            })
        logger.info(f"JSON file: loaded {len(findings)} findings from {path}")
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
    except Exception as e:
        logger.error(f"JSON file load failed: {e}")
    return findings


def fetch_csv_file(path: str) -> List[Dict]:
    """Import findings from a CSV file."""
    findings = []
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                findings.append({
                    "title":       row.get("title", row.get("name", "CSV Finding")),
                    "severity":    _norm_sev(row.get("severity", row.get("risk", "medium"))),
                    "category":    row.get("category", row.get("module", "manual")),
                    "source":      f"csv:{Path(path).name}",
                    "description": row.get("description", ""),
                    "target":      row.get("target", row.get("host", "")),
                    "cve":         row.get("cve", ""),
                    "cvss":        float(row.get("cvss", 0) or 0),
                    "ts":          row.get("timestamp", _now()),
                    "raw":         dict(row),
                })
        logger.info(f"CSV file: loaded {len(findings)} findings from {path}")
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
    except Exception as e:
        logger.error(f"CSV load failed: {e}")
    return findings


def fetch_cef_file(path: str, max_lines: int = 10000) -> List[Dict]:
    """Parse a CEF (Common Event Format) syslog file."""
    import re
    findings = []
    cef_re = re.compile(
        r"CEF:\d+\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|(?P<name>[^|]*)\|(?P<sev>[^|]*)\|(?P<ext>.*)")
    try:
        with open(path, errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= max_lines:
                    break
                m = cef_re.search(line.strip())
                if not m:
                    continue
                d = m.groupdict()
                ext: Dict[str, str] = {}
                for kv in re.finditer(r'(\w+)=((?:[^\\=\s]|\\.)+)', d["ext"]):
                    ext[kv.group(1)] = kv.group(2)
                try:
                    si = int(d["sev"].strip())
                    sev = ("critical" if si >= 9 else "high" if si >= 7
                           else "medium" if si >= 4 else "low")
                except ValueError:
                    sev = _norm_sev(d["sev"])
                findings.append({
                    "title":       d["name"].strip(),
                    "severity":    sev,
                    "category":    "siem",
                    "source":      f"cef:{Path(path).name}",
                    "description": d["name"].strip(),
                    "target":      ext.get("dst", ext.get("destinationAddress", "")),
                    "ts":          ext.get("end", ext.get("rt", _now())),
                    "raw":         {**d, "ext": ext},
                })
        logger.info(f"CEF file: parsed {len(findings)} events from {path}")
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
    except Exception as e:
        logger.error(f"CEF parse failed: {e}")
    return findings


class IntegrationManager:
    """Orchestrates data ingestion from all configured security data sources."""

    def __init__(self):
        self._cfg = _load_config()

    def _c(self, section: str, key: str) -> str:
        return _resolve(self._cfg.get(section, {}).get(key, ""))

    def fetch_all(self) -> List[Dict]:
        """Fetch from all configured sources. Returns unified findings list."""
        all_findings: List[Dict] = []

        # Splunk
        splunk_url = self._c("splunk", "url") or os.environ.get("AURORA_SPLUNK_URL", "")
        splunk_tok = self._c("splunk", "token") or os.environ.get("AURORA_SPLUNK_TOKEN", "")
        if splunk_url and splunk_tok:
            all_findings.extend(fetch_splunk(splunk_url, splunk_tok,
                                             self._c("splunk", "search_query") or None))
        elif splunk_url:
            logger.warning("Splunk URL configured but token missing — skipping")

        # Elastic SIEM
        el_url = self._c("elastic", "url") or os.environ.get("AURORA_ELASTIC_URL", "")
        el_key = self._c("elastic", "api_key") or os.environ.get("AURORA_ELASTIC_API_KEY", "")
        if el_url and el_key:
            all_findings.extend(fetch_elastic(el_url, el_key,
                                              self._c("elastic", "index") or ".siem-signals-*"))
        elif el_url:
            logger.warning("Elastic URL configured but api_key missing — skipping")

        # Wazuh
        wz_url  = self._c("wazuh", "url")      or os.environ.get("AURORA_WAZUH_URL", "")
        wz_user = self._c("wazuh", "username") or os.environ.get("AURORA_WAZUH_USER", "")
        wz_pass = self._c("wazuh", "password") or os.environ.get("AURORA_WAZUH_PASS", "")
        if wz_url and wz_user and wz_pass:
            all_findings.extend(fetch_wazuh(wz_url, wz_user, wz_pass))
        elif wz_url:
            logger.warning("Wazuh URL configured but credentials missing — skipping")

        # MISP
        misp_url = self._c("misp", "url")     or os.environ.get("AURORA_MISP_URL", "")
        misp_key = self._c("misp", "api_key") or os.environ.get("AURORA_MISP_KEY", "")
        if misp_url and misp_key:
            all_findings.extend(fetch_misp(misp_url, misp_key))
        elif misp_url:
            logger.warning("MISP URL configured but api_key missing — skipping")

        # File sources
        for fc in self._cfg.get("files", []):
            ftype = fc.get("type", "json")
            fpath = _resolve(fc.get("path", ""))
            if not fpath:
                continue
            if ftype in ("json", "kryphorix"):
                all_findings.extend(fetch_json_file(fpath))
            elif ftype == "csv":
                all_findings.extend(fetch_csv_file(fpath))
            elif ftype == "cef":
                all_findings.extend(fetch_cef_file(fpath))
            else:
                logger.warning(f"Unknown file source type: {ftype}")

        if not all_findings:
            logger.info(
                "No integration sources returned data. "
                "Configure ~/.aurora/integrations.json to connect live sources.")

        logger.info(f"Integration fetch complete: {len(all_findings)} total findings")
        return all_findings

    def status(self) -> Dict:
        """Return configured/unconfigured status for all sources."""
        out = {}
        for src in ["splunk", "elastic", "wazuh", "misp"]:
            url = self._c(src, "url") or os.environ.get(f"AURORA_{src.upper()}_URL", "")
            out[src] = "configured" if url else "not configured"
        out["files"] = f"{len(self._cfg.get('files', []))} file source(s)"
        return out
