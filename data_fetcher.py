import requests
import pandas as pd

def fetch_cisa_data():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    return response.json()

def process_cisa_data(cisa_data):
    vulnerabilities = cisa_data['vulnerabilities']
    df = pd.DataFrame(vulnerabilities)
    df['dateAdded'] = pd.to_datetime(df['dateAdded'])
    df['dueDate'] = pd.to_datetime(df['dueDate'])
    
    # Fetch EPSS and CVSS scores for each CVE
    df['EPSS'] = df['cveID'].apply(fetch_epss_score)
    df['CVSS3'] = df['cveID'].apply(fetch_cvss_base_score)
    
    return df

def fetch_epss_score(cve):
    url = f"https://api.first.org/data/v1/epss?cve={cve}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if data['status'] == 'OK' and data['total'] > 0:
            return float(data['data'][0]['epss'])
    return None

def fetch_cvss_base_score(cve):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
            try:
                base_score = float(data['vulnerabilities'][0]["cve"]['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'])
                return base_score
            except (KeyError, ValueError):
                pass
    return None
