"""Threat-intelligence provider registry.

Providers are independent adapters; each can be enabled or disabled by
supplying (or omitting) its API key in the environment. A missing key yields
status NOT CONFIGURED and never crashes the application.
"""
from .. import config
from .base import ThreatIntelProvider, ProviderResult, http_get_json  # noqa: F401
from .base import (STATUS_OK, STATUS_NOT_CONFIGURED, STATUS_UNAVAILABLE,  # noqa: F401
                   STATUS_NO_RESULT, STATUS_UNSUPPORTED)
from .virustotal import VirusTotalProvider
from .abuseipdb import AbuseIPDBProvider
from .otx import OTXProvider
from .greynoise import GreyNoiseProvider
from .geoip import GeoIPProvider


def get_providers():
    return [
        VirusTotalProvider(config.VIRUSTOTAL_API_KEY),
        AbuseIPDBProvider(config.ABUSEIPDB_API_KEY),
        OTXProvider(config.OTX_API_KEY),
        GreyNoiseProvider(config.GREYNOISE_API_KEY),
        GeoIPProvider(),
    ]


def provider_statuses():
    return [p.status() for p in get_providers()]


def query_all(itype: str, indicator: str):
    """Run every configured provider for an indicator; return list of results."""
    results = []
    for provider in get_providers():
        if itype not in provider.supports:
            continue
        results.append(provider.lookup(itype, indicator))
    return results
