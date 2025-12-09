
import requests
import os

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

url = 'https://accounts.google.com/.well-known/openid-configuration'

try:
    print(f"Attempting to fetch {url}...")
    response = requests.get(url, timeout=5)
    print(f"Status Code: {response.status_code}")
    print("Content preview:", response.text[:100])
except Exception as e:
    print("FAILED")
    print(e)
