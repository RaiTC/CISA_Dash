import os
import json
import requests
import pandas as pd
from datetime import datetime
import time
import tempfile
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

CACHE_FILE = 'data_cache.json'
LEGACY_DIR = 'Legacy'
NVD_KEY = os.getenv("NVD_KEY")  # Access the API key from environment variables
NVD_SLEEPTIME = 6  # NVD Recommended sleep time

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

    # Fetch EPSS and CVSS scores for each CVE if not already available
    if 'EPSS' not in df.columns:
        df['EPSS'] = df['cveID'].apply(fetch_epss_score)
    if 'CVSS3' not in df.columns:
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
    headers = {'apiKey': NVD_KEY}
    response = requests.get(url, headers=headers)
    
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
    
    time.sleep(NVD_SLEEPTIME)  # NVD Recommendation
    return None

def load_cached_data():
    print("Loading cached data...")
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as file:
                data = json.load(file)
                # Convert date strings back to datetime
                for key in ['dateAdded', 'dueDate']:
                    for idx in data['processed_data'][key]:
                        data['processed_data'][key][idx] = pd.to_datetime(data['processed_data'][key][idx])
                return data
        except json.JSONDecodeError as e:
            print(f"Error loading cached data: {e}")
            # Optionally, back up the corrupted cache file
            os.rename(CACHE_FILE, f"{CACHE_FILE}.bak")
            return None
    return None

def save_cached_data(cisa_data, processed_data):
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
    
    # Convert DataFrame to JSON-serializable format
    for col in processed_data.select_dtypes(['datetime']):
        processed_data[col] = processed_data[col].apply(lambda x: x.isoformat() if isinstance(x, pd.Timestamp) else x)

    cisa_data['processed_data'] = processed_data.to_dict()

    # Write to a temporary file first and then rename to avoid partial writes
    with tempfile.NamedTemporaryFile('w', delete=False) as tmp_file:
        json.dump(cisa_data, tmp_file, indent=4)
        tmp_file_path = tmp_file.name
    
    os.rename(tmp_file_path, CACHE_FILE)
    print("Cached data saved successfully.")

def get_latest_data():
    print("Starting data fetching process...")
    cisa_data = fetch_cisa_data()
    cached_data = load_cached_data()
    if cached_data is None or cached_data['catalogVersion'] != cisa_data['catalogVersion']:
        print("New data available. Updating cache...")
        processed_data = process_cisa_data(cisa_data)
        save_cached_data(cisa_data, processed_data)
        return processed_data
    print("Using cached data...")
    cached_df = pd.DataFrame(cached_data['processed_data'])

    return cached_df
