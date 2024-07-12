import os
import json
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException
import urllib.parse
from tqdm import tqdm

# Configuration
USER = '<username>'
PASSWORD = '<password>'
PAGE_SIZE = 500
PORTAL_URL = "<portal-url>" # e.g. "https://<name>-portal.asimily.com" 
ASSET_ENDPOINT = "/api/extapi/assets"
CVE_ENDPOINT = "/api/extapi/assets/cves"
EXPORT_DIR = "output"
MAX_RETRIES = 3
INITIAL_WAIT_TIME = 10  # Initial wait time in seconds

# E.g. Leave empty to fetch all assets
# PARAMS = {}
# E.g. Filter parameters: device Family = 'Medical Devices'
PARAMS = { 'deviceFamily': ['Medical Devices']}
SORT_PARAMS = 'defaultSort'
URL_PARAMS = urllib.parse.urlencode(PARAMS, quote_via=urllib.parse.quote, doseq=True)

def construct_url(base, *paths, **query_params):
    url = base.rstrip('/')
    for path in paths:
        url += '/' + path.strip('/')
    if query_params:
        url += '?' + urllib.parse.urlencode(query_params, doseq=True)
    return url

# Construct asset URL
ASSET_URL = construct_url(PORTAL_URL, ASSET_ENDPOINT, size=PAGE_SIZE, sort=SORT_PARAMS, **PARAMS)

# Create output directory
OUTPUT_DIRECTORY = os.path.join(os.getcwd(), EXPORT_DIR)
os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)

def make_api_call(user, password, url):
    """Makes a GET request to the given URL with basic auth and returns the response JSON data."""
    attempt = 0
    while attempt < MAX_RETRIES:
        try:
            response = requests.get(url, auth=HTTPBasicAuth(user, password))
            response.raise_for_status()
            return response.json()
        except RequestException as e:
            print(f"Exception occurred while fetching data for URL: {url}")
            print('-' * 50)
            print(f"Attempt {attempt + 1} failed. Error: {e}")
            print('-' * 50)
            attempt += 1
            if attempt < MAX_RETRIES:
                wait_time = INITIAL_WAIT_TIME * 2 ** attempt
                print(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
    
    print(f"Maximum retries ({MAX_RETRIES}) exceeded. Unable to fetch data from URL: {url}")
    return {}

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
        records.extend(initial_data.get('content', []))

        
        for page_num in range(1, total_pages):
            url = f"{ASSET_URL}&page={page_num}"
            print(f"[info] fetching asset data for page: {page_num}")
            page_data = make_api_call(USER, PASSWORD, url)
            records.extend(page_data.get('content', []))
                

        print("~" * 90)
        print(f"Total records: {len(records)}")

        if records:
            with tqdm(total=len(records), desc="Asset Export Progress") as pbar:
                for asset in records :
                    #print(f"[info] fetching asset: {asset['deviceID']}")
                    cve_url = construct_url(PORTAL_URL, CVE_ENDPOINT, str(asset['deviceID']))
                    cve_records = make_api_call(USER, PASSWORD, cve_url)
                    write_to_file(asset, cve_records)
                    pbar.update(1)

            print(f"Successfully exported asset records to folder: {export_dir}")
            print("~" * 90)
        else:
            print("~" * 90)
            print("No records found to export")
            print("~" * 90)
    else:
        print("~" * 90)
        print("Please check: Nothing to export")
        print("~" * 90)

def fetch_device_vulnerabilities(asset):
    """Fetch Vulnerabilities for a given asset."""
    # print(f"[info] fetching asset: {asset['deviceID']}")
    cve_url = construct_url(PORTAL_URL, CVE_ENDPOINT, str(asset['deviceID']))
    return make_api_call(USER, PASSWORD, cve_url)

def write_to_file(asset, cve):
    """Writes asset and vulnerabilities data to respective JSON files in the output directory."""
    device_filename = os.path.join(OUTPUT_DIRECTORY, f"{asset['deviceID']}.json")
    cve_filename = os.path.join(OUTPUT_DIRECTORY, f"{asset['deviceID']}_cve.json")

    with open(device_filename, 'w') as device_file:
        json.dump(asset, device_file, separators=(',', ':'))

    with open(cve_filename, 'w') as cve_file:
        json.dump(cve, cve_file, separators=(',', ':'))

if __name__ == "__main__":
    # Invoke method to export assets with specified filter criteria
    export_assets(EXPORT_DIR)