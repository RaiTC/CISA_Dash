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
    return df

if __name__ == "__main__":
    cisa_data = fetch_cisa_data()
    cisa_df = process_cisa_data(cisa_data)
    print(cisa_df.head())
