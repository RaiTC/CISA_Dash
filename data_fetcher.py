import os
import json
import requests
import pandas as pd
from datetime import datetime
import time
import tempfile
import shutil
from dotenv import load_dotenv
import subprocess

# Load environment variables from .env file
load_dotenv()

CACHE_FILE = 'data_cache.json'
LEGACY_DIR = 'Legacy'
NVD_KEY = os.getenv("NVD_KEY")  # Access the API key from environment variables
NVD_SLEEPTIME = 6  # NVD Recommended sleep time
GITHUB_REPO_URL = os.getenv("GITHUB_REPO_URL")
GITHUB_U = os.getenv("GITHUB_U")
GITHUB_T= os.getenv("GITHUB_T")
GITHUB_E = os.getenv("GITHUB_E")
GITHUB_BRANCH = 'main'

def fetch_cisa_data():
    print("Fetching data from CISA...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    return response.json()

def process_cisa_data(cisa_data, cached_data):
    print("Processing CISA data...")
    vulnerabilities = cisa_data['vulnerabilities']
    df = pd.DataFrame(vulnerabilities)
    df['dateAdded'] = pd.to_datetime(df['dateAdded'])
    df['dueDate'] = pd.to_datetime(df['dueDate'])

    cached_cves = set(cached_data['cveID']) if cached_data is not None else set()
    
    # Identify new CVEs
    new_cves = df[~df['cveID'].isin(cached_cves)].copy()
    print(f"Found {len(new_cves)} new CVEs.")
    
    # Fetch EPSS and CVSS scores for new CVEs only
    if not new_cves.empty:
        new_cves['EPSS'] = new_cves['cveID'].apply(fetch_epss_score)
        new_cves['CVSS3'] = new_cves['cveID'].apply(fetch_cvss_base_score)

        # Ensure None values are handled
        new_cves['EPSS'] = new_cves['EPSS'].fillna(0)
        new_cves['CVSS3'] = new_cves['CVSS3'].fillna(0)

        # Combine new CVEs with cached data
        if cached_data is not None:
            combined_data = pd.concat([cached_data, new_cves], ignore_index=True)
        else:
            combined_data = new_cves
    else:
        combined_data = cached_data

    return combined_data

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
                
                if 'cvssMetricV31' in cvss_metrics and len(cvss_metrics['cvssMetricV31']) > 0:
                    return cvss_metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                
                elif 'cvssMetricV30' in cvss_metrics and len(cvss_metrics['cvssMetricV30']) > 0:
                    return cvss_metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                
                elif 'cvssMetricV2' in cvss_metrics and len(cvss_metrics['cvssMetricV2']) > 0:
                    return cvss_metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                
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
                    data['processed_data'][key] = {k: pd.to_datetime(v) for k, v in data['processed_data'][key].items()}
                cached_data = pd.DataFrame(data['processed_data'])
                return cached_data, data.get('catalogVersion', None)
        except json.JSONDecodeError as e:
            print(f"Error loading cached data: {e}")
            # Optionally, back up the corrupted cache file
            os.rename(CACHE_FILE, f"{CACHE_FILE}.bak")
            return None, None
    return None, None

def save_cached_data(cisa_data, processed_data):
    print("Saving cached data...")
    
    if not os.path.exists(LEGACY_DIR):
        os.makedirs(LEGACY_DIR)
    
    # Backup old cache
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
    
    # Convert NaN to None for numerical data
    processed_data = processed_data.fillna(value=pd.NA).replace({pd.NA: None})
    
    cisa_data['processed_data'] = processed_data.to_dict()

    # Write to a temporary file first and then rename to avoid partial writes
    with tempfile.NamedTemporaryFile('w', delete=False) as tmp_file:
        json.dump(cisa_data, tmp_file, indent=4)
        tmp_file_path = tmp_file.name
    
    shutil.move(tmp_file_path, CACHE_FILE)
    print("Cached data saved successfully.")
    
    # Commit and push changes to GitHub
    commit_and_push_changes([CACHE_FILE, legacy_file])

def commit_and_push_changes(files_to_commit):
    try:
        print("Committing and pushing changes to GitHub...")
        # Configure git
        subprocess.run(['git', 'config', '--global', 'user.email', GITHUB_E], check=True)
        subprocess.run(['git', 'config', '--global', 'user.name', GITHUB_U], check=True)
        
        # Add specific files
        for file in files_to_commit:
            subprocess.run(['git', 'add', file], check=True)
        
        # Commit changes
        subprocess.run(['git', 'commit', '-m', 'Update data cache and legacy files'], check=True)
        
        # Push changes
        repo_url_with_token = f"https://{GITHUB_U}:{GITHUB_T}@{GITHUB_REPO_URL.split('https://')[1]}"
        subprocess.run(['git', 'push', repo_url_with_token], check=True)
        print("Changes pushed to GitHub successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error committing and pushing changes: {e}")
        print(f"Command output: {e.output}")

def get_latest_data():
    print("Starting data fetching process...")
    cisa_data = fetch_cisa_data()
    cached_data, cached_catalog_version = load_cached_data()
    
    if cached_data is None or cached_catalog_version != cisa_data['catalogVersion']:
        print("New data available. Updating cache...")
        processed_data = process_cisa_data(cisa_data, cached_data)
        save_cached_data(cisa_data, processed_data)
        return processed_data

    print("Using cached data...")
    cached_data['dateAdded'] = pd.to_datetime(cached_data['dateAdded'])
    cached_data['dueDate'] = pd.to_datetime(cached_data['dueDate'])

    return cached_data

def update_legacy_data():
    repo_url = GITHUB_REPO_URL
    repo_url_with_token = f"https://{GITHUB_U}:{GITHUB_T}@{repo_url.split('https://')[1]}"
    
    try:
        # If Legacy directory does not exist, create it
        if not os.path.exists(LEGACY_DIR):
            os.makedirs(LEGACY_DIR)
            print("Legacy directory created.")
        
        # Move to Legacy directory
        current_dir = os.getcwd()
        os.chdir(LEGACY_DIR)
        
        # Initialize a new git repository in Legacy folder if not already initialized
        if not os.path.exists('.git'):
            subprocess.run(['git', 'init'], check=True)
            subprocess.run(['git', 'remote', 'add', 'origin', repo_url_with_token], check=True)
            print("Initialized new Git repository in Legacy directory.")
        
        # Fetch the latest state from the remote repository
        subprocess.run(['git', 'fetch', '--all'], check=True)
        subprocess.run(['git', 'reset', '--hard', 'origin/main'], check=True)
        
        # Change back to the original directory
        os.chdir(current_dir)
    
    except subprocess.CalledProcessError as e:
        print(f"Error updating legacy data: {e}")
        print(f"Command output: {e.output}")
        os.chdir(current_dir)


if __name__ == "__main__":
    update_legacy_data()
    get_latest_data()
