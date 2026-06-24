import os
import json
import time
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException
import urllib.parse
from tqdm import tqdm

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
USER = '<username>'
PASSWORD = '<password>'
SOURCE = '<YourOrganizationName>'  # Alphabetic only. Mandatory as of May 1, 2026.
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

SORT_PARAMS = ''

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


PARAMS = {'deviceFamily': ['Medical Devices']}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

OUTPUT_DIRECTORY = os.path.join(os.getcwd(), EXPORT_DIR)
os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)

HEADERS = {
    'source': SOURCE,
    'Content-Type': 'application/json',
}


def construct_url(base, *paths, **query_params):
    url = base.rstrip('/')
    for path in paths:
        url += '/' + path.strip('/')
    if query_params:
        url += '?' + urllib.parse.urlencode(query_params, doseq=True)
    return url


def _request(method, url, user, password, json_body=None):
    """Core HTTP request with retry logic. Supports GET, POST, PUT, PATCH."""
    attempt = 0
    while attempt < MAX_RETRIES:
        try:
            response = requests.request(
                method,
                url,
                auth=HTTPBasicAuth(user, password),
                headers=HEADERS,
                json=json_body,
            )
            response.raise_for_status()
            if response.status_code == 204 or not response.content:
                return {}
            return response.json()
        except RequestException as e:
            print(f"[{method}] Attempt {attempt + 1} failed for {url}. Error: {e}")
            attempt += 1
            if attempt < MAX_RETRIES:
                wait_time = INITIAL_WAIT_TIME * (2 ** (attempt - 1))
                print(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
    print(f"Maximum retries ({MAX_RETRIES}) exceeded for {url}")
    return {}


def make_api_call(user, password, url):
    """GET request."""
    return _request('GET', url, user, password)


def make_api_post(user, password, url, body):
    """POST request with JSON body."""
    return _request('POST', url, user, password, json_body=body)


def make_api_put(user, password, url):
    """PUT request (no body)."""
    return _request('PUT', url, user, password)


def make_api_patch(user, password, url, body):
    """PATCH request with JSON body."""
    return _request('PATCH', url, user, password, json_body=body)


# ---------------------------------------------------------------------------
# Asset — Fetch Asset Details  (GET /api/extapi/assets)
# ---------------------------------------------------------------------------

ASSET_URL = construct_url(PORTAL_URL, ASSET_ENDPOINT, size=PAGE_SIZE, sort=SORT_PARAMS, **PARAMS)


def export_assets(export_dir):
    """Fetches and exports all assets matching filter criteria to the specified output directory"""
    print("-" * 50)
    print(f"Exporting asset data for site: {PORTAL_URL}")
    print("Filters:")
    for k, v in PARAMS.items():
        print(f"\t{k}: {v}")
    print("-" * 50)

    records = []
    initial_data = make_api_call(USER, PASSWORD, f"{ASSET_URL}&page=0")

    if initial_data:
        total_pages = initial_data.get('totalPages', 0)
        print(f"[info] total pages: {total_pages}")
        records.extend(initial_data.get('content', []))

        for page_num in range(1, total_pages):
            url = f"{ASSET_URL}&page={page_num}"
            print(f"[info] fetching page {page_num}")
            page_data = make_api_call(USER, PASSWORD, url)
            records.extend(page_data.get('content', []))

        print("~" * 90)
        print(f"Total records: {len(records)}")

        if records:
            with tqdm(total=len(records), desc="Asset Export Progress") as pbar:
                for asset in records:
                    cve_url = construct_url(PORTAL_URL, CVE_ENDPOINT, str(asset['deviceID']))
                    cve_records = make_api_call(USER, PASSWORD, cve_url)
                    write_to_file(asset, f"{asset['deviceID']}.json")
                    write_to_file(cve_records, f"{asset['deviceID']}_cve.json")
                    pbar.update(1)
            print(f"Successfully exported to: {export_dir}")
        else:
            print("No records found to export")
        print("~" * 90)
    else:
        print("Nothing to export — check credentials / filters")


def write_to_file(data, filename):
    """
    Write any API response data to a JSON file in the output directory.

    Args:
        data:     Any JSON-serialisable object (dict, list, etc.).
        filename: Output filename (e.g. 'device_5_ports.json').
                  The file is always written under OUTPUT_DIRECTORY.

    Examples:
        write_to_file(asset, f"{asset['deviceID']}.json")
        write_to_file(cve_records, f"{asset['deviceID']}_cve.json")
        write_to_file(ports, 'device_5_ports.json')
        write_to_file(all_cves_page, 'all_cves_page_0.json')
    """
    filepath = os.path.join(OUTPUT_DIRECTORY, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, separators=(',', ': '))
    print(f"Saved: {filepath}")


# ---------------------------------------------------------------------------
# Asset — Update Device Attributes  (PATCH /api/extapi/assets/{deviceId})
# ---------------------------------------------------------------------------

def update_device_attributes(device_id, is_device_segmented=None, device_tags=None):
    """
    Update device segmentation status and/or device tags.

    Args:
        device_id: Asimily device ID (integer).
        is_device_segmented: True to mark device as auto-segmented (bool, optional).
        device_tags: Comma-separated tag string, e.g. "BioMed Managed,High Risk Device" (optional).

    Returns:
        {} on success (HTTP 204), or error dict.

    Examples:
        update_device_attributes(730570, is_device_segmented=True)
        update_device_attributes(730570, device_tags="slot_0,slot_01")
        update_device_attributes(206153, device_tags="BioMed Managed,High Risk Device")
        update_device_attributes(730570, is_device_segmented=True, device_tags="slot_0,slot_01")
    """
    body = {}
    if is_device_segmented is not None:
        body['isDeviceSegmented'] = is_device_segmented
    if device_tags is not None:
        body['deviceTag'] = device_tags
    if not body:
        raise ValueError("At least one of is_device_segmented or device_tags must be provided")

    url = construct_url(PORTAL_URL, ASSET_ENDPOINT, str(device_id))
    result = make_api_patch(USER, PASSWORD, url, body)
    print(f"update_device_attributes({device_id}): {result or 'success'}")
    return result


# ---------------------------------------------------------------------------
# Asset — Fetch Device Ports  (GET /api/extapi/assets/port)
# Identify a device by exactly one of: macAddr, ipAddr, or deviceId.
# Wildcards and CIDR are NOT supported — exact match only.
# ---------------------------------------------------------------------------

def fetch_device_ports(device_id=None, mac_addr=None, ip_addr=None, page=0, size=None):
    """
    Fetch network ports for a single device.

    Args:
        device_id: Asimily device ID (int, optional).
        mac_addr:  Exact MAC address string (optional).
        ip_addr:   Exact IP address string (optional).
        page:      Zero-based page index (default 0).
        size:      Max ports per page (default: API max 10000).

    Returns:
        List of port records.

    Examples:
        fetch_device_ports(mac_addr='<mac-address>')
        fetch_device_ports(mac_addr='<mac-address>', page=0, size=500)
        fetch_device_ports(device_id=5)
    """
    params = {'page': page}
    if size is not None:
        params['size'] = size
    if mac_addr:
        params['macAddr'] = mac_addr
    elif ip_addr:
        params['ipAddr'] = ip_addr
    elif device_id is not None:
        params['deviceId'] = device_id
    else:
        raise ValueError("Provide one of: device_id, mac_addr, or ip_addr")

    url = construct_url(PORTAL_URL, PORT_ENDPOINT, **params)
    return make_api_call(USER, PASSWORD, url)


# ---------------------------------------------------------------------------
# Asset — Fetch Device Applications  (GET /api/extapi/assets/application)
# Identify a device by exactly one of: macAddr, ipAddr, or deviceId.
# Wildcards and CIDR are NOT supported — exact match only.
# ---------------------------------------------------------------------------

def fetch_device_applications(device_id=None, mac_addr=None, ip_addr=None, page=0, size=None):
    """
    Fetch applications installed on a single device.

    Args:
        device_id: Asimily device ID (int, optional).
        mac_addr:  Exact MAC address string (optional).
        ip_addr:   Exact IP address string (optional).
        page:      Zero-based page index (default 0).
        size:      Max records per page (default: API max 10000).

    Returns:
        List of application records.

    Examples:
        fetch_device_applications(mac_addr='<mac-address>')
        fetch_device_applications(mac_addr='<mac-address>', page=0, size=500)
        fetch_device_applications(device_id=5)
    """
    params = {'page': page}
    if size is not None:
        params['size'] = size
    if mac_addr:
        params['macAddr'] = mac_addr
    elif ip_addr:
        params['ipAddr'] = ip_addr
    elif device_id is not None:
        params['deviceId'] = device_id
    else:
        raise ValueError("Provide one of: device_id, mac_addr, or ip_addr")

    url = construct_url(PORTAL_URL, APPLICATION_ENDPOINT, **params)
    return make_api_call(USER, PASSWORD, url)


# ---------------------------------------------------------------------------
# Asset — Bulk Fetch Devices Applications and Ports
# (GET /api/extapi/assets/device-apps-ports)
# Maximum 100 device IDs per call.
# ---------------------------------------------------------------------------

def fetch_bulk_apps_and_ports(device_ids):
    """
    Fetch applications and ports for up to 100 devices in one call.

    Args:
        device_ids: List of integer device IDs (max 100).

    Returns:
        List of records, each containing deviceID, applications, and ports.

    Example:
        fetch_bulk_apps_and_ports([739865, 172330, 1709, 2933, 820])
    """
    if len(device_ids) > 100:
        raise ValueError("Maximum 100 device IDs per request")
    ids_param = ','.join(str(d) for d in device_ids)
    url = construct_url(PORTAL_URL, BULK_APPS_PORTS_ENDPOINT, deviceIds=ids_param)
    return make_api_call(USER, PASSWORD, url)


# ---------------------------------------------------------------------------
# Anomaly — Fetch Device Anomalies  (GET /api/extapi/assets/anomaly)
# Identify a device by exactly one of: macAddr, ipAddr, or deviceId.
# Wildcards and CIDR are NOT supported — exact match only.
# ---------------------------------------------------------------------------

def fetch_device_anomalies(device_id=None, mac_addr=None, ip_addr=None,
                           criticality=None, is_fixed=None, page=0, size=None):
    """
    Fetch anomalies for a single device.

    Args:
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
        fetch_device_anomalies(mac_addr='<mac-address>')
        fetch_device_anomalies(mac_addr='<mac-address>', page=0, size=500)
        fetch_device_anomalies(ip_addr='<ip-address>')
        fetch_device_anomalies(device_id=3547)
        fetch_device_anomalies(device_id=3547, criticality='HIGH')
        fetch_device_anomalies(device_id=3547, is_fixed='FIXED')
    """
    params = {'page': page}
    if size is not None:
        params['size'] = size
    if mac_addr:
        params['macAddr'] = mac_addr
    elif ip_addr:
        params['ipAddr'] = ip_addr
    elif device_id is not None:
        params['deviceId'] = device_id
    else:
        raise ValueError("Provide one of: device_id, mac_addr, or ip_addr")
    if criticality:
        params['anomaliesCriticality'] = criticality
    if is_fixed:
        params['isAnomaliesFixed'] = is_fixed

    url = construct_url(PORTAL_URL, ANOMALY_ENDPOINT, **params)
    return make_api_call(USER, PASSWORD, url)


# ---------------------------------------------------------------------------
# Anomaly — Fetch All Anomalies  (POST /api/extapi/assets/anomalies)
# Paginated. Supports filters via JSON body.
# ---------------------------------------------------------------------------

def fetch_all_anomalies(page=0, size=100, sort='', filters=None):
    """
    Fetch all anomalies across all devices (paginated POST).

    Args:
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
        fetch_all_anomalies()
        fetch_all_anomalies(filters={'anomaliesCriticality': [{'operator': ':', 'value': 'HIGH'}]})
        fetch_all_anomalies(filters={'deviceFamily': [
            {'operator': ':', 'value': 'Medical Devices'},
            {'operator': ':', 'value': 'Laboratory Devices'},
        ]})
        fetch_all_anomalies(filters={'deviceTag': [{'operator': ':', 'value': 'Only Broadcast/DNS Traffic Received'}]})
        fetch_all_anomalies(filters={'deviceRangeId': [{'operator': '>', 'value': 153}]})
        fetch_all_anomalies(filters={'anomaliesLastUpdatedSince': [{'operator': '>', 'value': '2025-01-01'}]})
    """
    url = construct_url(PORTAL_URL, ALL_ANOMALIES_ENDPOINT, page=page, size=size, sort=sort)
    body = {'filters': filters or {}}
    return make_api_post(USER, PASSWORD, url, body)


# ---------------------------------------------------------------------------
# Anomaly — Fix Anomaly  (PUT /api/extapi/assets/anomalyfix)
# alertId format: "<deviceId>:<customerAnomalyId>"
# ---------------------------------------------------------------------------

def fix_anomaly(alert_id):
    """
    Mark a specific anomaly as fixed (fix action recorded as 'Manual').

    Args:
        alert_id: Unique anomaly alert ID in the format '<deviceId>:<customerAnomalyId>',
                  e.g. '564945:080457'. Retrieve deviceId and customerAnomalyId from
                  fetch_device_anomalies() response fields.

    Returns:
        {'message': 'Anomaly Fixed Successfully'} on success.

    Example:
        fix_anomaly('564945:080457')
    """
    url = construct_url(PORTAL_URL, FIX_ANOMALY_ENDPOINT, alertId=alert_id)
    return make_api_put(USER, PASSWORD, url)


# ---------------------------------------------------------------------------
# Vulnerability — Fetch Device CVEs  (GET /api/extapi/assets/cves)
# Identify a device by exactly one of: macAddr, ipAddr, or deviceId.
# Wildcards and CIDR are NOT supported — exact match only.
# ---------------------------------------------------------------------------

def fetch_device_vulnerabilities(device_id=None, mac_addr=None, ip_addr=None,
                                  cve_name=None, is_fixed=None, page=0, size=None):
    """
    Fetch CVEs for a single device.

    Args:
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
        fetch_device_vulnerabilities(mac_addr='<mac-address>')
        fetch_device_vulnerabilities(mac_addr='<mac-address>', page=0, size=500)
        fetch_device_vulnerabilities(device_id=4494)
        fetch_device_vulnerabilities(ip_addr='<ip-address>')
        fetch_device_vulnerabilities(ip_addr='<ip-address>', cve_name='CVE-2021-42279')
        fetch_device_vulnerabilities(device_id=21366, is_fixed='FIXED')
    """
    params = {'page': page}
    if size is not None:
        params['size'] = size
    if mac_addr:
        params['macAddr'] = mac_addr
    elif ip_addr:
        params['ipAddr'] = ip_addr
    elif device_id is not None:
        params['deviceId'] = device_id
    else:
        raise ValueError("Provide one of: device_id, mac_addr, or ip_addr")
    if cve_name:
        params['cveName'] = cve_name
    if is_fixed:
        params['isCvesFixed'] = is_fixed

    url = construct_url(PORTAL_URL, CVE_ENDPOINT, **params)
    return make_api_call(USER, PASSWORD, url)


# ---------------------------------------------------------------------------
# Vulnerability — Fetch All CVEs  (POST /api/extapi/assets/device-cves)
# Paginated. Supports filters via JSON body.
# ---------------------------------------------------------------------------

def fetch_all_cves(page=0, size=100, sort='', filters=None):
    """
    Fetch all CVEs across all devices (paginated POST).

    Args:
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

    Returns:
        Paginated response with 'content', 'totalPages', 'totalElements'.

    Examples:
        fetch_all_cves()
        fetch_all_cves(filters={'cveScore': [{'operator': 'Gte', 'value': 7.5}]})
        fetch_all_cves(filters={'deviceFamily': [
            {'operator': ':', 'value': 'Medical Devices'},
            {'operator': ':', 'value': 'Laboratory Devices'},
        ]})
        fetch_all_cves(filters={'deviceTag': [{'operator': ':', 'value': 'Only Broadcast/DNS Traffic Received'}]})
        fetch_all_cves(sort='deviceInfoId', filters={'deviceRangeId': [{'operator': '>', 'value': 166929}]})
        fetch_all_cves(filters={'cvesLastUpdatedSince': [{'operator': '>', 'value': '2025-01-01'}]})
    """
    url = construct_url(PORTAL_URL, ALL_CVES_ENDPOINT, page=page, size=size, sort=sort)
    body = {'filters': filters or {}}
    return make_api_post(USER, PASSWORD, url, body)


# ---------------------------------------------------------------------------
# Vulnerability — Fix CVE  (POST /api/extapi/assets/cvefix)
# Max 50 device IDs per call. Pass [-1] to fix for all associated devices.
# ---------------------------------------------------------------------------

def fix_cve(cve_name, device_ids):
    """
    Mark a CVE as fixed for the specified devices.

    Args:
        cve_name:   CVE identifier string, e.g. 'CVE-2021-1722'.
        device_ids: List of integer device IDs (max 50), or [-1] to fix for all devices.

    Returns:
        {'message': '...', 'jobId': <int>}

    Examples:
        fix_cve('CVE-2021-1722', [195802, 118390])   # fix for specific devices
        fix_cve('CVE-2021-1722', [-1])                # fix for all associated devices
    """
    if device_ids != [-1] and len(device_ids) > 50:
        raise ValueError("Maximum 50 device IDs per request (or use [-1] for all)")
    url = construct_url(PORTAL_URL, FIX_CVE_ENDPOINT)
    body = {'cveName': cve_name, 'deviceIds': device_ids}
    return make_api_post(USER, PASSWORD, url, body)


# ---------------------------------------------------------------------------
# Recall — Fetch Device Recalls  (GET /api/extapi/assets/recall)
# Identify a device by exactly one of: macAddr, ipAddr, or deviceId.
# Wildcards and CIDR are NOT supported — exact match only.
# ---------------------------------------------------------------------------

def fetch_device_recalls(device_id=None, mac_addr=None, ip_addr=None, page=0, size=None):
    """
    Fetch FDA recall information for a single device.

    Args:
        device_id: Asimily device ID (int, optional).
        mac_addr:  Exact MAC address string (optional).
        ip_addr:   Exact IP address string (optional).
        page:      Zero-based page index (default 0).
        size:      Max records per page (default: API max 10000).

    Returns:
        List of recall records including 'recallNumber', 'recallStatus', and 'internalRecallStatus'.

    Examples:
        fetch_device_recalls(mac_addr='<mac-address>')
        fetch_device_recalls(mac_addr='<mac-address>', page=0, size=500)
        fetch_device_recalls(device_id=5)
    """
    params = {'page': page}
    if size is not None:
        params['size'] = size
    if mac_addr:
        params['macAddr'] = mac_addr
    elif ip_addr:
        params['ipAddr'] = ip_addr
    elif device_id is not None:
        params['deviceId'] = device_id
    else:
        raise ValueError("Provide one of: device_id, mac_addr, or ip_addr")

    url = construct_url(PORTAL_URL, RECALL_ENDPOINT, **params)
    return make_api_call(USER, PASSWORD, url)


# ---------------------------------------------------------------------------
# Recall — Fix Recall  (PATCH /api/extapi/assets/recall/{recallNum})
# Max 100 device IDs per call. Pass [-1] to fix for all associated devices.
# deviceIds is mandatory and must not be empty.
# ---------------------------------------------------------------------------

def fix_recall(recall_number, device_ids):
    """
    Mark a recall as fixed for the specified devices.

    Args:
        recall_number: Recall number string, e.g. 'Z-0020-2025'.
        device_ids:    List of integer device IDs (max 100), or [-1] to fix for all devices.

    Returns:
        {'message': '...', 'jobId': <int>}

    Examples:
        fix_recall('Z-0020-2025', [195802, 118390])   # fix for specific devices
        fix_recall('Z-0020-2025', [-1])                # fix for all associated devices
    """
    if not device_ids:
         raise ValueError("device_ids must not be empty (or use [-1] for all)")
    if device_ids != [-1] and len(device_ids) > 100:
        raise ValueError("Maximum 100 device IDs per request (or use [-1] for all)")
    url = construct_url(PORTAL_URL, RECALL_ENDPOINT, recall_number)
    body = {'deviceIds': device_ids}
    return make_api_patch(USER, PASSWORD, url, body)


# ---------------------------------------------------------------------------
# Entry point — sample usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # --- Asset export (paginated, writes JSON files to output/) ---
    export_assets(EXPORT_DIR)

    # --- Fetch device ports ---
    # ports = fetch_device_ports(mac_addr='<mac-address>')
    # ports = fetch_device_ports(device_id=5)
    # write_to_file(ports, 'device_5_ports.json')

    # --- Fetch device applications ---
    # apps = fetch_device_applications(mac_addr='<mac-address>')
    # apps = fetch_device_applications(device_id=5)
    # write_to_file(apps, 'device_5_apps.json')

    # --- Bulk fetch applications + ports (max 100 device IDs) ---
    # bulk = fetch_bulk_apps_and_ports([739865, 172330, 1709, 2933, 820])
    # write_to_file(bulk, 'bulk_apps_ports.json')

    # --- Update device attributes ---
    # update_device_attributes(730570, is_device_segmented=True)
    # update_device_attributes(730570, device_tags='slot_0,slot_01')
    # update_device_attributes(206153, device_tags='BioMed Managed,High Risk Device')
    # update_device_attributes(730570, is_device_segmented=True, device_tags='slot_0,slot_01')

    # --- Fetch anomalies for a device ---
    # anomalies = fetch_device_anomalies(mac_addr='<mac-address>')
    # anomalies = fetch_device_anomalies(device_id=3547, criticality='HIGH')
    # anomalies = fetch_device_anomalies(device_id=3547, is_fixed='NOT_FIXED')
    # write_to_file(anomalies, 'device_3547_anomalies.json')

    # --- Fetch all anomalies (paginated POST) ---
    # all_anomalies = fetch_all_anomalies()
    # all_anomalies = fetch_all_anomalies(filters={'anomaliesCriticality': [{'operator': ':', 'value': 'HIGH'}]})
    # all_anomalies = fetch_all_anomalies(filters={'deviceRangeId': [{'operator': '>', 'value': 153}]})
    # all_anomalies = fetch_all_anomalies(filters={'anomaliesLastUpdatedSince': [{'operator': '>', 'value': '2025-01-01'}]})
    # write_to_file(all_anomalies, 'all_anomalies_page_0.json')

    # --- Fix anomaly ---
    # result = fix_anomaly('564945:080457')
    # print(result)

    # --- Fetch CVEs for a device ---
    # cves = fetch_device_vulnerabilities(mac_addr='<mac-address>')
    # cves = fetch_device_vulnerabilities(ip_addr='<ip-address>', cve_name='CVE-2021-42279')
    # cves = fetch_device_vulnerabilities(device_id=21366, is_fixed='FIXED')
    # write_to_file(cves, 'device_21366_cves.json')

    # --- Fetch all CVEs (paginated POST) ---
    # all_cves = fetch_all_cves()
    # all_cves = fetch_all_cves(filters={'cveScore': [{'operator': 'Gte', 'value': 7.5}]})
    # all_cves = fetch_all_cves(sort='deviceInfoId', filters={'deviceRangeId': [{'operator': '>', 'value': 166929}]})
    # all_cves = fetch_all_cves(filters={'cvesLastUpdatedSince': [{'operator': '>', 'value': '2025-01-01'}]})
    # write_to_file(all_cves, 'all_cves_page_0.json')

    # --- Fix CVE ---
    # result = fix_cve('CVE-2021-1722', [195802, 118390])
    # result = fix_cve('CVE-2021-1722', [-1])  # fix for all associated devices
    # print(result)

    # --- Fetch recalls for a device ---
    # recalls = fetch_device_recalls(mac_addr='<mac-address>')
    # recalls = fetch_device_recalls(device_id=5)
    # write_to_file(recalls, 'device_5_recalls.json')

    # --- Fix recall ---
    # result = fix_recall('Z-0020-2025', [195802, 118390])
    # result = fix_recall('Z-0020-2025', [-1])  # fix for all associated devices
    # print(result)
