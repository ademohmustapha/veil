"""
AURORA Integrations Layer
==========================
Connects AURORA to live data sources: SIEM platforms, vulnerability
scanners, and threat intelligence feeds.

Usage:
    from integrations import IntegrationManager
    mgr = IntegrationManager()
    findings = mgr.fetch_all()     # returns list of normalised Finding dicts
    print(mgr.status())            # shows configured / unconfigured sources
"""
from integrations.manager import IntegrationManager

__all__ = ["IntegrationManager"]
