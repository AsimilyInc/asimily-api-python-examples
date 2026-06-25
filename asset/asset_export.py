from __future__ import annotations

# Requires Python 3.10+.
import os
import json
import time
import urllib.parse
from typing import Any, Callable

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException
from tqdm import tqdm

# ==============================================================================
# Copyright (c) 2026 Asimily, Inc. All rights reserved.
#
# This software and associated documentation files (the "Software") are the
# proprietary and confidential property of Asimily, Inc.
#
# Unauthorized copying, modification, distribution, or use of this file and
# its contents, via any medium, without the express written permission and
# a valid Software License Agreement from Asimily, Inc. is strictly prohibited.
# ==============================================================================

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
USER = '<username>'
PASSWORD = '<password>'
SOURCE = '<YourOrganizationName>'
PAGE_SIZE = 500
PORTAL_URL = "<portal-url>"  # e.g. "https://<name>-portal.asimily.com"
EXPORT_DIR = "output"
MAX_RETRIES = 3
INITIAL_WAIT_TIME = 10  # Initial wait time in seconds

# Endpoints
ASSET_ENDPOINT = "/api/extapi/assets"
CVE_ENDPOINT = "/api/extapi/assets/cves"
ALL_CVES_ENDPOINT = "/api/extapi/assets/device-cves"
FIX_CVE_ENDPOINT = "/api/extapi/assets/cvefix"
PORT_ENDPOINT = "/api/extapi/assets/port"
APPLICATION_ENDPOINT = "/api/extapi/assets/application"
BULK_APPS_PORTS_ENDPOINT = "/api/extapi/assets/device-apps-ports"
ANOMALY_ENDPOINT = "/api/extapi/assets/anomaly"
ALL_ANOMALIES_ENDPOINT = "/api/extapi/assets/anomalies"
FIX_ANOMALY_ENDPOINT = "/api/extapi/assets/anomalyfix"
RECALL_ENDPOINT = "/api/extapi/assets/recall"

DEFAULT_SORT = ''

# ---------------------------------------------------------------------------
# Asset filter parameters
# ---------------------------------------------------------------------------
# Leave empty to fetch all assets:
# PARAMS = {}
#
# Combining filters:
#   - Multiple keys = AND logic:
#     PARAMS = {'os': ['windows*'], 'riskGte': ['8'], 'deviceFamily': ['Medical Devices']}
#   - Multiple values for the same key = OR logic within that filter:
#     PARAMS = {'deviceFamily': ['Medical Devices', 'IT Devices']}
#   - Mix of both:
#     PARAMS = {'ipAddr': ['<ip-cidr-1>', '<ip-cidr-2>'], 'riskGte': ['7'], 'deviceTag': ['ephi']}
#
# Available filters (examples below use single values for clarity):
#
# --- Network ---
# PARAMS = {'ipAddr': ['<ip-cidr>']}                                  # IP Address (CIDR supported)
# PARAMS = {'macAddr': ['<mac-address>']}                             # MAC Address
# PARAMS = {'ipAddr': ['<ip-cidr>'], 'riskGte': ['8']}               # IP range AND risk score >= 8
#
# --- Device Identity ---
# PARAMS = {'deviceId': ['730570']}                                   # Device ID (exact)
# PARAMS = {'hostName': ['myhost*']}                                  # Hostname (wildcard supported)
# PARAMS = {'serialNumber': ['SN12345']}                              # Serial Number
# PARAMS = {'stationName': ['Station A']}                             # Station Name
#
# --- Classification ---
# PARAMS = {'deviceFamily': ['Medical Devices']}                      # Device Family
# PARAMS = {'deviceType': ['IT Workstation']}                         # Device Type
# PARAMS = {'deviceModel': ['CABLES / WIRES']}                        # Device Model
# PARAMS = {'manufacturer': ['MISC']}                                 # Manufacturer
# PARAMS = {'os': ['windows*']}                                       # OS (wildcard supported)
#
# --- Location / Organization ---
# PARAMS = {'facility': ['Main Campus']}                              # Facility
# PARAMS = {'department': ['Radiology']}                              # Department
# PARAMS = {'location': ['Floor 2']}                                  # Location
# PARAMS = {'region': ['US-West']}                                    # Region
# PARAMS = {'managedBy': ['IT']}                                      # Managed By
#
# --- Connectivity ---
# PARAMS = {'isConnected': ['true']}                                  # Device Connected (Boolean)
# PARAMS = {'isCurrentlyInUse': ['true']}                             # Currently in Use (Boolean)
# PARAMS = {'isWireless': ['Wireless']}                               # Connectivity (Wireless/Wired)
# PARAMS = {'devicesConnectedToSSID': ['CorpWiFi']}                   # Connected to SSID
# PARAMS = {'externalDomain': ['example.com']}                        # External Domain
# PARAMS = {'externalConnectivity': ['HTTP']}                         # External Connectivity By Service
# PARAMS = {'externalConnectivityByCountry': ['China']}               # External Connectivity By Country
# PARAMS = {'externalConnectivityByManufacturer': ['Amazon']}         # External Connectivity By Organization
# PARAMS = {'externalConnectivityByReputation': ['Malicious']}        # External Connectivity By Reputation
#
# --- Risk & Scoring ---
# PARAMS = {'riskGte': ['8']}                                         # Risk Score >= 8
# PARAMS = {'riskGrt': ['7']}                                         # Risk Score > 7
# PARAMS = {'riskLte': ['5']}                                         # Risk Score <= 5
# PARAMS = {'riskLst': ['6']}                                         # Risk Score < 6
# PARAMS = {'impactGte': ['8']}                                       # Impact >= 8
# PARAMS = {'impactGrt': ['7']}                                       # Impact > 7
# PARAMS = {'impactLte': ['5']}                                       # Impact <= 5
# PARAMS = {'impactLst': ['6']}                                       # Impact < 6
# PARAMS = {'likelihoodGte': ['8']}                                   # Likelihood >= 8
# PARAMS = {'likelihoodGrt': ['7']}                                   # Likelihood > 7
# PARAMS = {'likelihoodLte': ['5']}                                   # Likelihood <= 5
# PARAMS = {'likelihoodLst': ['6']}                                   # Likelihood < 6
# PARAMS = {'anomaly': ['true']}                                       # Anomaly Present (Boolean)
#
# --- Software & Services ---
# PARAMS = {'service': ['SSH']}                                       # Service
# PARAMS = {'application': ['Chrome']}                                # Application
# PARAMS = {'securityCapabilities': ['Antivirus']}                    # Security Capabilities
#
# --- Compliance & Tags ---
# PARAMS = {'mds2DocState': ['Available']}                            # Devices with MDS2
# PARAMS = {'ephi': ['true']}                                         # ePHI
# PARAMS = {'deviceTag': ['ephi']}                                    # Device Tag
# PARAMS = {'cmmsId': ['HURON']}                                      # CMMS ID
#
# --- Discovery & Status ---
# PARAMS = {'discoveredOver': ['3 month']}                            # Discovered Over (e.g. '6 days', '3 month')
# PARAMS = {'devicesNotSeenSince': ['2024-01-01']}                    # Devices Not Seen Since (YYYY-MM-DD)
# PARAMS = {'devicesSeenSince': ['2024-01-01']}                       # Devices Seen Since (YYYY-MM-DD)
# PARAMS = {'discoverySourceValue': ['Nmap']}                         # Discovery Source
# PARAMS = {'isDeviceDeActivated': ['false']}                         # Deactivated (Boolean)
#
# PARAMS = {'hasUniqueIP': ['Yes']}                                   # Has Unique IP (String Yes or No)


PARAMS: dict[str, list[str]] = {'deviceFamily': ['Medical Devices']}


# ---------------------------------------------------------------------------
# URL helper
# ---------------------------------------------------------------------------

def construct_url(base: str, *paths: str, **query_params: Any) -> str:
    """Build a URL from a base, optional path segments, and query parameters."""
    url = base.rstrip('/')
    for path in paths:
        url += '/' + path.strip('/')
    if query_params:
        url += '?' + urllib.parse.urlencode(query_params, doseq=True)
    return url


# ---------------------------------------------------------------------------
# Device-identifier resolution  (shared by all single-device fetch functions)
# ---------------------------------------------------------------------------

def _resolve_device_params(
    params: dict[str, Any],
    device_id: int | None,
    mac_addr: str | None,
    ip_addr: str | None,
) -> None:
    """
    Mutate *params* with exactly one device identifier.

    Raises ValueError if zero or more than one identifier is provided.
    """
    provided = [x for x in (mac_addr, ip_addr, device_id) if x is not None]
    if len(provided) > 1:
        raise ValueError(
            "Provide exactly one of: device_id, mac_addr, or ip_addr "
            f"(got {len(provided)})"
        )
    if mac_addr is not None:
        params['macAddr'] = mac_addr
    elif ip_addr is not None:
        params['ipAddr'] = ip_addr
    elif device_id is not None:
        params['deviceId'] = device_id
    else:
        raise ValueError("Provide one of: device_id, mac_addr, or ip_addr")


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class ApiClient:
    """
    Authenticated HTTP client for the Asimily REST API.

    Encapsulates credentials, retry logic, header management, and file I/O
    so domain functions stay free of global state.

    Args:
        portal_url:   Base portal URL, e.g. "https://acme-portal.asimily.com".
        user:         API username.
        password:     API password.
        source:       Organisation name sent in the 'source' header.
        export_dir:   Directory for JSON output files (created if absent).
        max_retries:  Number of HTTP retry attempts.
        initial_wait: Base wait (seconds) for exponential back-off.
    """

    def __init__(
        self,
        portal_url: str,
        user: str,
        password: str,
        source: str,
        export_dir: str = "output",
        max_retries: int = MAX_RETRIES,
        initial_wait: int = INITIAL_WAIT_TIME,
    ) -> None:
        self.portal_url = portal_url.rstrip('/')
        self._auth = HTTPBasicAuth(user, password)
        self._headers = {'source': source, 'Content-Type': 'application/json'}
        self.output_dir = os.path.join(os.getcwd(), export_dir)
        self.max_retries = max_retries
        self.initial_wait = initial_wait
        os.makedirs(self.output_dir, exist_ok=True)

    # --- URL construction ---

    def url(self, *paths: str, **query_params: Any) -> str:
        """Build a full URL relative to this client's portal_url."""
        return construct_url(self.portal_url, *paths, **query_params)

    # --- Low-level HTTP with retry ---

    def _request(self, method: str, url: str, json_body: Any = None) -> dict[str, Any]:
        """Execute an HTTP request with exponential back-off retry."""
        for attempt in range(self.max_retries):
            try:
                response = requests.request(
                    method,
                    url,
                    auth=self._auth,
                    headers=self._headers,
                    json=json_body,
                    timeout=30,
                )
                response.raise_for_status()
                if response.status_code == 204 or not response.content:
                    return {}
                return response.json()
            except (RequestException, ValueError) as e:
                print(f"[{method}] Attempt {attempt + 1} failed for {url}. Error: {e}")
                if attempt < self.max_retries - 1:
                    wait = self.initial_wait * (2 ** attempt)
                    print(f"Retrying in {wait}s...")
                    time.sleep(wait)
        print(f"Maximum retries ({self.max_retries}) exceeded for {url}")
        return {}

    # --- HTTP verb helpers ---

    def get(self, url: str) -> dict[str, Any]:
        """GET request."""
        return self._request('GET', url)

    def post(self, url: str, body: Any) -> dict[str, Any]:
        """POST request with JSON body."""
        return self._request('POST', url, json_body=body)

    def put(self, url: str) -> dict[str, Any]:
        """PUT request (no body)."""
        return self._request('PUT', url)

    def patch(self, url: str, body: Any) -> dict[str, Any]:
        """PATCH request with JSON body."""
        return self._request('PATCH', url, json_body=body)

    # --- File I/O ---

    def write_to_file(self, data: Any, filename: str) -> None:
        """
        Write *data* as formatted JSON to *filename* inside output_dir.

        Uses tqdm.write so output does not break active progress bars.
        """
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, separators=(',', ': '))
        tqdm.write(f"Saved: {filepath}")


# ---------------------------------------------------------------------------
# Pagination export helper
# ---------------------------------------------------------------------------

def _export_paginated(
    client: ApiClient,
    fetch_fn: Callable[..., dict[str, Any]],
    desc: str,
    filename: str,
    size: int = 500,
    sort: str = '',
    filters: dict[str, Any] | None = None,
) -> None:
    """
    Fetch all pages from a paginated POST endpoint and write to a single file.

    Args:
        client:   ApiClient instance used for file I/O.
        fetch_fn: Callable with signature fetch_fn(page, size, sort, filters).
        desc:     tqdm progress bar label.
        filename: Output JSON filename.
        size:     Records per page (max 500).
        sort:     Sort field string.
        filters:  Filter conditions dict.
    """
    first_page = fetch_fn(page=0, size=size, sort=sort, filters=filters)
    if not first_page:
        print(f"No data returned for '{desc}' — check credentials / filters")
        return

    total_pages = int(first_page.get('totalPages') or 1)
    records: list[Any] = list(first_page.get('content', []))

    with tqdm(total=total_pages, desc=desc) as pbar:
        pbar.update(1)
        for page_num in range(1, total_pages):
            page_data = fetch_fn(page=page_num, size=size, sort=sort, filters=filters)
            records.extend(page_data.get('content', []))
            pbar.update(1)

    client.write_to_file(records, filename)
    print(f"Total records exported: {len(records)}")


# ---------------------------------------------------------------------------
# Asset — Fetch Asset Details  (GET /api/extapi/assets)
# ---------------------------------------------------------------------------

def export_assets(
    client: ApiClient,
    params: dict[str, list[str]],
    page_size: int = PAGE_SIZE,
    sort: str = DEFAULT_SORT,
) -> None:
    """
    Fetch all assets matching *params* and export per-device JSON files.

    Each device produces two files: <deviceID>.json and <deviceID>_cve.json.

    Args:
        client:    Authenticated ApiClient.
        params:    Filter parameters (see PARAMS reference at top of file).
        page_size: Assets per page.
        sort:      Sort field string.
    """
    asset_url = client.url(ASSET_ENDPOINT, size=page_size, sort=sort, **params)

    print("-" * 50)
    print(f"Exporting asset data for site: {client.portal_url}")
    print("Filters:")
    for k, v in params.items():
        print(f"\t{k}: {v}")
    print("-" * 50)

    initial_data = client.get(f"{asset_url}&page=0")
    if not initial_data:
        print("Nothing to export — check credentials / filters")
        return

    total_pages = int(initial_data.get('totalPages') or 1)
    print(f"[info] total pages: {total_pages}")
    records: list[Any] = list(initial_data.get('content', []))

    for page_num in range(1, total_pages):
        print(f"[info] fetching page {page_num}")
        page_data = client.get(f"{asset_url}&page={page_num}")
        records.extend(page_data.get('content', []))

    print("~" * 90)
    print(f"Total records: {len(records)}")

    if not records:
        print("No records found to export")
        return

    with tqdm(total=len(records), desc="Asset Export Progress") as pbar:
        for asset in records:
            cve_records = fetch_device_vulnerabilities(client, device_id=asset['deviceID'])
            client.write_to_file(asset, f"{asset['deviceID']}.json")
            client.write_to_file(cve_records, f"{asset['deviceID']}_cve.json")
            pbar.update(1)

    print(f"Successfully exported to: {client.output_dir}")
    print("~" * 90)


# ---------------------------------------------------------------------------
# Asset — Update Device Attributes  (PATCH /api/extapi/assets/{deviceId})
# ---------------------------------------------------------------------------

def update_device_attributes(
    client: ApiClient,
    device_id: int,
    is_device_segmented: bool | None = None,
    device_tags: str | None = None,
) -> dict[str, Any]:
    """
    Update device segmentation status and/or device tags.

    Args:
        client:              Authenticated ApiClient.
        device_id:           Asimily device ID.
        is_device_segmented: True to mark as auto-segmented (optional).
        device_tags:         Comma-separated tag string, e.g. "BioMed Managed,High Risk Device" (optional).

    Returns:
        {} on success (HTTP 204), or error dict.

    Examples:
        update_device_attributes(client, 730570, is_device_segmented=True)
        update_device_attributes(client, 730570, device_tags="slot_0,slot_01")
        update_device_attributes(client, 206153, device_tags="BioMed Managed,High Risk Device")
        update_device_attributes(client, 730570, is_device_segmented=True, device_tags="slot_0,slot_01")
    """
    body: dict[str, Any] = {}
    if is_device_segmented is not None:
        body['isDeviceSegmented'] = is_device_segmented
    if device_tags is not None:
        body['deviceTag'] = device_tags
    if not body:
        raise ValueError("At least one of is_device_segmented or device_tags must be provided")

    url = client.url(ASSET_ENDPOINT, str(device_id))
    result = client.patch(url, body)
    print(f"update_device_attributes({device_id}): {result or 'success'}")
    return result


# ---------------------------------------------------------------------------
# Asset — Fetch Device Ports  (GET /api/extapi/assets/port)
# Identify a device by exactly one of: macAddr, ipAddr, or deviceId.
# Wildcards and CIDR are NOT supported — exact match only.
# ---------------------------------------------------------------------------

def fetch_device_ports(
    client: ApiClient,
    device_id: int | None = None,
    mac_addr: str | None = None,
    ip_addr: str | None = None,
    page: int = 0,
    size: int | None = None,
) -> dict[str, Any]:
    """
    Fetch network ports for a single device.

    Args:
        client:    Authenticated ApiClient.
        device_id: Asimily device ID (int, optional).
        mac_addr:  Exact MAC address string (optional).
        ip_addr:   Exact IP address string (optional).
        page:      Zero-based page index (default 0).
        size:      Max ports per page (default: API max 10000).

    Returns:
        List of port records.

    Examples:
        fetch_device_ports(client, mac_addr='<mac-address>')
        fetch_device_ports(client, mac_addr='<mac-address>', page=0, size=500)
        fetch_device_ports(client, device_id=5)
    """
    params: dict[str, Any] = {'page': page}
    if size is not None:
        params['size'] = size
    _resolve_device_params(params, device_id, mac_addr, ip_addr)
    return client.get(client.url(PORT_ENDPOINT, **params))


# ---------------------------------------------------------------------------
# Asset — Fetch Device Applications  (GET /api/extapi/assets/application)
# Identify a device by exactly one of: macAddr, ipAddr, or deviceId.
# Wildcards and CIDR are NOT supported — exact match only.
# ---------------------------------------------------------------------------

def fetch_device_applications(
    client: ApiClient,
    device_id: int | None = None,
    mac_addr: str | None = None,
    ip_addr: str | None = None,
    page: int = 0,
    size: int | None = None,
) -> dict[str, Any]:
    """
    Fetch applications installed on a single device.

    Args:
        client:    Authenticated ApiClient.
        device_id: Asimily device ID (int, optional).
        mac_addr:  Exact MAC address string (optional).
        ip_addr:   Exact IP address string (optional).
        page:      Zero-based page index (default 0).
        size:      Max records per page (default: API max 10000).

    Returns:
        List of application records.

    Examples:
        fetch_device_applications(client, mac_addr='<mac-address>')
        fetch_device_applications(client, mac_addr='<mac-address>', page=0, size=500)
        fetch_device_applications(client, device_id=5)
    """
    params: dict[str, Any] = {'page': page}
    if size is not None:
        params['size'] = size
    _resolve_device_params(params, device_id, mac_addr, ip_addr)
    return client.get(client.url(APPLICATION_ENDPOINT, **params))


# ---------------------------------------------------------------------------
# Asset — Bulk Fetch Devices Applications and Ports
# (GET /api/extapi/assets/device-apps-ports)
# Maximum 100 device IDs per call.
# ---------------------------------------------------------------------------

def fetch_bulk_apps_and_ports(
    client: ApiClient,
    device_ids: list[int],
) -> dict[str, Any]:
    """
    Fetch applications and ports for up to 100 devices in one call.

    Args:
        client:     Authenticated ApiClient.
        device_ids: List of integer device IDs (max 100).

    Returns:
        List of records, each containing deviceID, applications, and ports.

    Example:
        fetch_bulk_apps_and_ports(client, [739865, 172330, 1709, 2933, 820])
    """
    if len(device_ids) > 100:
        raise ValueError("Maximum 100 device IDs per request")
    ids_param = ','.join(str(d) for d in device_ids)
    return client.get(client.url(BULK_APPS_PORTS_ENDPOINT, deviceIds=ids_param))


# ---------------------------------------------------------------------------
# Anomaly — Fetch Device Anomalies  (GET /api/extapi/assets/anomaly)
# Identify a device by exactly one of: macAddr, ipAddr, or deviceId.
# Wildcards and CIDR are NOT supported — exact match only.
# ---------------------------------------------------------------------------

def fetch_device_anomalies(
    client: ApiClient,
    device_id: int | None = None,
    mac_addr: str | None = None,
    ip_addr: str | None = None,
    criticality: str | None = None,
    is_fixed: str | None = None,
    page: int = 0,
    size: int | None = None,
) -> dict[str, Any]:
    """
    Fetch anomalies for a single device.

    Args:
        client:      Authenticated ApiClient.
        device_id:   Asimily device ID (int, optional).
        mac_addr:    Exact MAC address string (optional).
        ip_addr:     Exact IP address string (optional).
        criticality: Filter by severity — 'HIGH', 'MEDIUM', or 'LOW' (optional).
        is_fixed:    Filter by fix status — 'FIXED' or 'NOT_FIXED' (optional).
        page:        Zero-based page index (default 0).
        size:        Max records per page (default: API max 10000).

    Returns:
        List of anomaly records.

    Examples:
        fetch_device_anomalies(client, mac_addr='<mac-address>')
        fetch_device_anomalies(client, mac_addr='<mac-address>', page=0, size=500)
        fetch_device_anomalies(client, ip_addr='<ip-address>')
        fetch_device_anomalies(client, device_id=3547)
        fetch_device_anomalies(client, device_id=3547, criticality='HIGH')
        fetch_device_anomalies(client, device_id=3547, is_fixed='FIXED')
    """
    params: dict[str, Any] = {'page': page}
    if size is not None:
        params['size'] = size
    _resolve_device_params(params, device_id, mac_addr, ip_addr)
    if criticality:
        params['anomaliesCriticality'] = criticality
    if is_fixed:
        params['isAnomaliesFixed'] = is_fixed
    return client.get(client.url(ANOMALY_ENDPOINT, **params))


# ---------------------------------------------------------------------------
# Anomaly — Fetch All Anomalies  (POST /api/extapi/assets/anomalies)
# Paginated. Supports filters via JSON body.
# ---------------------------------------------------------------------------

def fetch_all_anomalies(
    client: ApiClient,
    page: int = 0,
    size: int = 100,
    sort: str = '',
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Fetch all anomalies across all devices (paginated POST).

    Args:
        client:  Authenticated ApiClient.
        page:    Page number (default 0).
        size:    Records per page, max 500 (default 100).
        sort:    Sort field string (default '').
        filters: Dict of filter conditions (default: no filters).

    Filter options:
        anomaliesCriticality  — 'HIGH', 'MEDIUM', or 'LOW'
        deviceFamily          — multi-value, e.g. ['Medical Devices', 'Laboratory Devices']
        deviceTag             — multi-value, e.g. ['Only Broadcast/DNS Traffic Received']
        deviceRangeId         — fetch in batches by internal device ID (operator '>')
        anomaliesLastUpdatedSince — ISO date string (operator '>')

    Returns:
        Paginated response with 'content', 'totalPages', 'totalElements'.

    Examples:
        fetch_all_anomalies(client)
        fetch_all_anomalies(client, filters={'anomaliesCriticality': [{'operator': ':', 'value': 'HIGH'}]})
        fetch_all_anomalies(client, filters={'deviceFamily': [
            {'operator': ':', 'value': 'Medical Devices'},
            {'operator': ':', 'value': 'Laboratory Devices'},
        ]})
        fetch_all_anomalies(client, filters={'deviceTag': [{'operator': ':', 'value': 'Only Broadcast/DNS Traffic Received'}]})
        fetch_all_anomalies(client, filters={'deviceRangeId': [{'operator': '>', 'value': 153}]})
        fetch_all_anomalies(client, filters={'anomaliesLastUpdatedSince': [{'operator': '>', 'value': '2025-01-01'}]})
    """
    url = client.url(ALL_ANOMALIES_ENDPOINT, page=page, size=size, sort=sort)
    return client.post(url, {'filters': filters or {}})


# ---------------------------------------------------------------------------
# Anomaly — Export All Anomalies (paginated, with progress bar)
# ---------------------------------------------------------------------------

def export_all_anomalies(
    client: ApiClient,
    filename: str,
    size: int = 500,
    sort: str = '',
    filters: dict[str, Any] | None = None,
) -> None:
    """
    Fetch all anomaly pages and write the combined records to a single JSON file.

    Args:
        client:   Authenticated ApiClient.
        filename: Output filename (e.g. 'all_anomalies.json').
        size:     Records per page, max 500 (default 500).
        sort:     Sort field string (default '').
        filters:  Dict of filter conditions (default: no filters).

    Examples:
        export_all_anomalies(client, 'all_anomalies.json')
        export_all_anomalies(client, 'high_anomalies.json',
                             filters={'anomaliesCriticality': [{'operator': ':', 'value': 'HIGH'}]})
    """
    _export_paginated(
        client,
        fetch_fn=lambda **kw: fetch_all_anomalies(client, **kw),
        desc="Anomaly Export Progress",
        filename=filename,
        size=size,
        sort=sort,
        filters=filters,
    )


# ---------------------------------------------------------------------------
# Anomaly — Fix Anomaly  (PUT /api/extapi/assets/anomalyfix)
# alertId format: "<deviceId>:<customerAnomalyId>"
# ---------------------------------------------------------------------------

def fix_anomaly(client: ApiClient, alert_id: str) -> dict[str, Any]:
    """
    Mark a specific anomaly as fixed (fix action recorded as 'Manual').

    Args:
        client:   Authenticated ApiClient.
        alert_id: Unique anomaly alert ID in the format '<deviceId>:<customerAnomalyId>',
                  e.g. '564945:080457'. Retrieve deviceId and customerAnomalyId from
                  fetch_device_anomalies() response fields.

    Returns:
        {'message': 'Anomaly Fixed Successfully'} on success.

    Example:
        fix_anomaly(client, '564945:080457')
    """
    return client.put(client.url(FIX_ANOMALY_ENDPOINT, alertId=alert_id))


# ---------------------------------------------------------------------------
# Vulnerability — Fetch Device CVEs  (GET /api/extapi/assets/cves)
# Identify a device by exactly one of: macAddr, ipAddr, or deviceId.
# Wildcards and CIDR are NOT supported — exact match only.
# ---------------------------------------------------------------------------

def fetch_device_vulnerabilities(
    client: ApiClient,
    device_id: int | None = None,
    mac_addr: str | None = None,
    ip_addr: str | None = None,
    cve_name: str | None = None,
    is_fixed: str | None = None,
    page: int = 0,
    size: int | None = None,
) -> dict[str, Any]:
    """
    Fetch CVEs for a single device.

    Args:
        client:    Authenticated ApiClient.
        device_id: Asimily device ID (int, optional).
        mac_addr:  Exact MAC address string (optional).
        ip_addr:   Exact IP address string (optional).
        cve_name:  Filter by specific CVE, e.g. 'CVE-2021-42279' (optional).
        is_fixed:  Filter by fix status — 'FIXED' or 'NOT_FIXED' (optional).
        page:      Zero-based page index (default 0).
        size:      Max records per page (default: API max 10000).

    Returns:
        List of CVE records.

    Examples:
        fetch_device_vulnerabilities(client, mac_addr='<mac-address>')
        fetch_device_vulnerabilities(client, mac_addr='<mac-address>', page=0, size=500)
        fetch_device_vulnerabilities(client, device_id=4494)
        fetch_device_vulnerabilities(client, ip_addr='<ip-address>')
        fetch_device_vulnerabilities(client, ip_addr='<ip-address>', cve_name='CVE-2021-42279')
        fetch_device_vulnerabilities(client, device_id=21366, is_fixed='FIXED')
    """
    params: dict[str, Any] = {'page': page}
    if size is not None:
        params['size'] = size
    _resolve_device_params(params, device_id, mac_addr, ip_addr)
    if cve_name:
        params['cveName'] = cve_name
    if is_fixed:
        params['isCvesFixed'] = is_fixed
    return client.get(client.url(CVE_ENDPOINT, **params))


# ---------------------------------------------------------------------------
# Vulnerability — Fetch All CVEs  (POST /api/extapi/assets/device-cves)
# Paginated. Supports filters via JSON body.
# ---------------------------------------------------------------------------

def fetch_all_cves(
    client: ApiClient,
    page: int = 0,
    size: int = 100,
    sort: str = '',
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Fetch all CVEs across all devices (paginated POST).

    Args:
        client:  Authenticated ApiClient.
        page:    Page number (default 0).
        size:    Records per page, max 500 (default 100).
        sort:    Sort field string (default '').
        filters: Dict of filter conditions (default: no filters).

    Filter options:
        cveScore              — operator must be 'Gte', value 7.5 or 4
        deviceFamily          — multi-value, e.g. ['Medical Devices', 'Laboratory Devices']
        deviceTag             — multi-value, e.g. ['Only Broadcast/DNS Traffic Received']
        deviceRangeId         — fetch in batches by internal device ID (operator '>')
        cvesLastUpdatedSince  — ISO date string (operator '>')
        cvesOpenedSince       — ISO date string (operator '>')

    Returns:
        Paginated response with 'content', 'totalPages', 'totalElements'.

    Examples:
        fetch_all_cves(client)
        fetch_all_cves(client, filters={'cveScore': [{'operator': 'Gte', 'value': 7.5}]})
        fetch_all_cves(client, filters={'deviceFamily': [
            {'operator': ':', 'value': 'Medical Devices'},
            {'operator': ':', 'value': 'Laboratory Devices'},
        ]})
        fetch_all_cves(client, filters={'deviceTag': [{'operator': ':', 'value': 'Only Broadcast/DNS Traffic Received'}]})
        fetch_all_cves(client, sort='deviceInfoId', filters={'deviceRangeId': [{'operator': '>', 'value': 166929}]})
        fetch_all_cves(client, filters={'cvesLastUpdatedSince': [{'operator': '>', 'value': '2025-01-01'}]})
        fetch_all_cves(client, filters={'cvesOpenedSince': [{'operator': '>', 'value': '2025-01-01'}]})
    """
    url = client.url(ALL_CVES_ENDPOINT, page=page, size=size, sort=sort)
    return client.post(url, {'filters': filters or {}})


# ---------------------------------------------------------------------------
# Vulnerability — Export All CVEs (paginated, with progress bar)
# ---------------------------------------------------------------------------

def export_all_cves(
    client: ApiClient,
    filename: str,
    size: int = 500,
    sort: str = '',
    filters: dict[str, Any] | None = None,
) -> None:
    """
    Fetch all CVE pages and write the combined records to a single JSON file.

    Args:
        client:   Authenticated ApiClient.
        filename: Output filename (e.g. 'all_cves.json').
        size:     Records per page, max 500 (default 500).
        sort:     Sort field string (default '').
        filters:  Dict of filter conditions (default: no filters).

    Examples:
        export_all_cves(client, 'all_cves.json')
        export_all_cves(client, 'critical_cves.json',
                        filters={'cveScore': [{'operator': 'Gte', 'value': 7.5}]})
    """
    _export_paginated(
        client,
        fetch_fn=lambda **kw: fetch_all_cves(client, **kw),
        desc="CVE Export Progress",
        filename=filename,
        size=size,
        sort=sort,
        filters=filters,
    )


# ---------------------------------------------------------------------------
# Vulnerability — Fix CVE  (POST /api/extapi/assets/cvefix)
# Max 50 device IDs per call. Pass [-1] to fix for all associated devices.
# ---------------------------------------------------------------------------

def fix_cve(
    client: ApiClient,
    cve_name: str,
    device_ids: list[int],
) -> dict[str, Any]:
    """
    Mark a CVE as fixed for the specified devices.

    Args:
        client:     Authenticated ApiClient.
        cve_name:   CVE identifier string, e.g. 'CVE-2021-1722'.
        device_ids: List of integer device IDs (max 50), or [-1] to fix for all devices.

    Returns:
        {'message': '...', 'jobId': <int>}

    Examples:
        fix_cve(client, 'CVE-2021-1722', [195802, 118390])   # fix for specific devices
        fix_cve(client, 'CVE-2021-1722', [-1])                # fix for all associated devices
    """
    if device_ids != [-1] and len(device_ids) > 50:
        raise ValueError("Maximum 50 device IDs per request (or use [-1] for all)")
    return client.post(
        client.url(FIX_CVE_ENDPOINT),
        {'cveName': cve_name, 'deviceIds': device_ids},
    )


# ---------------------------------------------------------------------------
# Recall — Fetch Device Recalls  (GET /api/extapi/assets/recall)
# Identify a device by exactly one of: macAddr, ipAddr, or deviceId.
# Wildcards and CIDR are NOT supported — exact match only.
# ---------------------------------------------------------------------------

def fetch_device_recalls(
    client: ApiClient,
    device_id: int | None = None,
    mac_addr: str | None = None,
    ip_addr: str | None = None,
    page: int = 0,
    size: int | None = None,
) -> dict[str, Any]:
    """
    Fetch FDA recall information for a single device.

    Args:
        client:    Authenticated ApiClient.
        device_id: Asimily device ID (int, optional).
        mac_addr:  Exact MAC address string (optional).
        ip_addr:   Exact IP address string (optional).
        page:      Zero-based page index (default 0).
        size:      Max records per page (default: API max 10000).

    Returns:
        List of recall records including 'recallNumber', 'recallStatus', and 'internalRecallStatus'.

    Examples:
        fetch_device_recalls(client, mac_addr='<mac-address>')
        fetch_device_recalls(client, mac_addr='<mac-address>', page=0, size=500)
        fetch_device_recalls(client, device_id=5)
    """
    params: dict[str, Any] = {'page': page}
    if size is not None:
        params['size'] = size
    _resolve_device_params(params, device_id, mac_addr, ip_addr)
    return client.get(client.url(RECALL_ENDPOINT, **params))


# ---------------------------------------------------------------------------
# Recall — Fix Recall  (PATCH /api/extapi/assets/recall/{recallNum})
# Max 100 device IDs per call. Pass [-1] to fix for all associated devices.
# deviceIds is mandatory and must not be empty.
# ---------------------------------------------------------------------------

def fix_recall(
    client: ApiClient,
    recall_number: str,
    device_ids: list[int],
) -> dict[str, Any]:
    """
    Mark a recall as fixed for the specified devices.

    Args:
        client:        Authenticated ApiClient.
        recall_number: Recall number string, e.g. 'Z-0020-2025'.
        device_ids:    List of integer device IDs (max 100), or [-1] to fix for all devices.

    Returns:
        {'message': '...', 'jobId': <int>}

    Examples:
        fix_recall(client, 'Z-0020-2025', [195802, 118390])   # fix for specific devices
        fix_recall(client, 'Z-0020-2025', [-1])                # fix for all associated devices
    """
    if not device_ids:
        raise ValueError("device_ids must not be empty (or use [-1] for all)")
    if device_ids != [-1] and len(device_ids) > 100:
        raise ValueError("Maximum 100 device IDs per request (or use [-1] for all)")
    return client.patch(
        client.url(RECALL_ENDPOINT, recall_number),
        {'deviceIds': device_ids},
    )


# ---------------------------------------------------------------------------
# Entry point — sample usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    client = ApiClient(
        portal_url=PORTAL_URL,
        user=USER,
        password=PASSWORD,
        source=SOURCE,
        export_dir=EXPORT_DIR,
    )

    # --- Asset export (paginated, writes JSON files to output/) ---
    export_assets(client, PARAMS)

    # --- Fetch device ports ---
    # ports = fetch_device_ports(client, mac_addr='<mac-address>')
    # ports = fetch_device_ports(client, device_id=5)
    # ports = fetch_device_ports(client, ip_addr='<ip-address>')
    # client.write_to_file(ports, 'device_5_ports.json')

    # --- Fetch device applications ---
    # apps = fetch_device_applications(client, mac_addr='<mac-address>')
    # apps = fetch_device_applications(client, device_id=5)
    # apps = fetch_device_applications(client, ip_addr='<ip-address>')
    # client.write_to_file(apps, 'device_5_apps.json')

    # --- Bulk fetch applications + ports (max 100 device IDs) ---
    # bulk = fetch_bulk_apps_and_ports(client, [739865, 172330, 1709, 2933, 820])
    # client.write_to_file(bulk, 'bulk_apps_ports.json')

    # --- Update device attributes ---
    # update_device_attributes(client, 730570, is_device_segmented=True)
    # update_device_attributes(client, 730570, device_tags='slot_0,slot_01')
    # update_device_attributes(client, 206153, device_tags='BioMed Managed,High Risk Device')
    # update_device_attributes(client, 730570, is_device_segmented=True, device_tags='slot_0,slot_01')

    # --- Fetch anomalies for a device ---
    # anomalies = fetch_device_anomalies(client, mac_addr='<mac-address>')
    # anomalies = fetch_device_anomalies(client, device_id=3547, criticality='HIGH')
    # anomalies = fetch_device_anomalies(client, device_id=3547, is_fixed='NOT_FIXED')
    # anomalies = fetch_device_anomalies(client, ip_addr='<ip-address>')
    # client.write_to_file(anomalies, 'device_3547_anomalies.json')

    # --- Fetch all anomalies (paginated POST, single page) ---
    # all_anomalies = fetch_all_anomalies(client)
    # all_anomalies = fetch_all_anomalies(client, filters={'anomaliesCriticality': [{'operator': ':', 'value': 'HIGH'}]})
    # all_anomalies = fetch_all_anomalies(client, filters={'deviceRangeId': [{'operator': '>', 'value': 153}]})
    # all_anomalies = fetch_all_anomalies(client, filters={'anomaliesLastUpdatedSince': [{'operator': '>', 'value': '2025-01-01'}]})
    # client.write_to_file(all_anomalies, 'all_anomalies_page_0.json')

    # --- Export ALL anomaly pages with progress bar ---
    # export_all_anomalies(client, 'all_anomalies.json')
    # export_all_anomalies(client, 'high_anomalies.json', filters={'anomaliesCriticality': [{'operator': ':', 'value': 'HIGH'}]})

    # --- Fix anomaly ---
    # result = fix_anomaly(client, '564945:080457')
    # print(result)

    # --- Fetch CVEs for a device ---
    # cves = fetch_device_vulnerabilities(client, mac_addr='<mac-address>')
    # cves = fetch_device_vulnerabilities(client, ip_addr='<ip-address>', cve_name='CVE-2021-42279')
    # cves = fetch_device_vulnerabilities(client, device_id=21366, is_fixed='FIXED')
    # client.write_to_file(cves, 'device_21366_cves.json')

    # --- Fetch all CVEs (paginated POST, single page) ---
    # all_cves = fetch_all_cves(client)
    # all_cves = fetch_all_cves(client, filters={'cveScore': [{'operator': 'Gte', 'value': 7.5}]})
    # all_cves = fetch_all_cves(client, sort='deviceInfoId', filters={'deviceRangeId': [{'operator': '>', 'value': 166929}]})
    # all_cves = fetch_all_cves(client, filters={'cvesLastUpdatedSince': [{'operator': '>', 'value': '2025-01-01'}]})
    # client.write_to_file(all_cves, 'all_cves_page_0.json')

    # --- Export ALL CVE pages with progress bar ---
    # export_all_cves(client, 'all_cves.json')
    # export_all_cves(client, 'critical_cves.json', filters={'cveScore': [{'operator': 'Gte', 'value': 7.5}]})

    # --- Fix CVE ---
    # result = fix_cve(client, 'CVE-2021-1722', [195802, 118390])
    # result = fix_cve(client, 'CVE-2021-1722', [-1])  # fix for all associated devices
    # print(result)

    # --- Fetch recalls for a device ---
    # recalls = fetch_device_recalls(client, mac_addr='<mac-address>')
    # recalls = fetch_device_recalls(client, device_id=5)
    # client.write_to_file(recalls, 'device_5_recalls.json')

    # --- Fix recall ---
    # result = fix_recall(client, 'Z-0020-2025', [195802, 118390])
    # result = fix_recall(client, 'Z-0020-2025', [-1])  # fix for all associated devices
    # print(result)
