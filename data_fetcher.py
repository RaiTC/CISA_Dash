import os
import json
import requests
import pandas as pd
from datetime import datetime

CACHE_FILE = 'data_cache.json'
LEGACY_DIR = 'Legacy'

def fetch_cisa_data():
    print("Fetching data from CISA...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    return response.json()

def process_cisa_data(cisa_data):
    print("Processing CISA data...")
    vulnerabilities = cisa_data['vulnerabilities']
    df = pd.DataFrame(vulnerabilities)
    df['dateAdded'] = pd.to_datetime(df['dateAdded'])
    df['dueDate'] = pd.to_datetime(df['dueDate'])
    
    # Fetch EPSS and CVSS scores for each CVE
    df['EPSS'] = df['cveID'].apply(fetch_epss_score)
    df['CVSS3'] = df['cveID'].apply(fetch_cvss_base_score)
    
    return df

def fetch_epss_score(cve):
    print(f"Fetching EPSS score for {cve}...")
    url = f"https://api.first.org/data/v1/epss?cve={cve}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if data['status'] == 'OK' and data['total'] > 0:
            return float(data['data'][0]['epss'])
    return None

def fetch_cvss_base_score(cve):
    print(f"Fetching CVSS base score for {cve}...")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
            try:
                cvss_metrics = data['vulnerabilities'][0]['cve']['metrics']
                
                # Check for CVSS v3.1 score
                if 'cvssMetricV31' in cvss_metrics and len(cvss_metrics['cvssMetricV31']) > 0:
                    base_score = cvss_metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    return base_score
                
                # Check for CVSS v3.0 score
                elif 'cvssMetricV30' in cvss_metrics and len(cvss_metrics['cvssMetricV30']) > 0:
                    base_score = cvss_metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                    return base_score
                
                # Check for CVSS v2.0 score as a fallback
                elif 'cvssMetricV2' in cvss_metrics and len(cvss_metrics['cvssMetricV2']) > 0:
                    base_score = cvss_metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                    return base_score
                
            except (KeyError, ValueError) as e:
                print(f"Error extracting CVSS base score for {cve}: {e}")
    else:
        print(f"Error fetching data for {cve}: HTTP {response.status_code}")
    return None

def load_cached_data():
    print("Loading cached data...")
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as file:
            return json.load(file)
    return None

def save_cached_data(cisa_data):
    print("Saving cached data...")
    if not os.path.exists(LEGACY_DIR):
        os.makedirs(LEGACY_DIR)
    catalog_version = cisa_data['catalogVersion']
    legacy_file = os.path.join(LEGACY_DIR, f"KEV_{catalog_version.replace('.', '')}.json")
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as file:
            old_data = json.load(file)
        with open(legacy_file, 'w') as file:
            json.dump(old_data, file, indent=4)
    with open(CACHE_FILE, 'w') as file:
        json.dump(cisa_data, file, indent=4)

def get_latest_data():
    print("Starting data fetching process...")
    cisa_data = fetch_cisa_data()
    cached_data = load_cached_data()
    if cached_data is None or cached_data['catalogVersion'] != cisa_data['catalogVersion']:
        print("New data available. Updating cache...")
        save_cached_data(cisa_data)
        return process_cisa_data(cisa_data)
    print("Using cached data...")
    return process_cisa_data(cached_data)
