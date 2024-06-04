from config import keyV, keyI
import requests
from geopy.geocoders import Nominatim
import matplotlib.pyplot as plt
import pandas as pd

base_url = "https://www.ipqualityscore.com/api/json/url/" + keyI + "/{}"
base_email= "https://www.ipqualityscore.com/api/json/email/"+keyI+"/{}"

base_url_V = ""
geolocator = Nominatim(user_agent="my_app")
country_code_url="https://www.ipqualityscore.com/api/json/country/list"

def get_data(url):
    resp = requests.get(url)
    return resp.json()


def get_coordinates(country_code):
    location = geolocator.geocode(country_code)
    if location:
        return location.latitude, location.longitude
    else:
        return None, None
    

def scan_url_virustotal(url):
    vt_url = "https://www.virustotal.com/vtapi/v2/url/scan"
    params = {'apikey': keyV, 'url': url}
    response = requests.post(vt_url, data=params)
    return response.json()

def get_url_report_virustotal(resource):
    vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': keyV, 'resource': resource}
    response = requests.get(vt_url, params=params)
    return response.json()

# def plot_virustotal_data(vt_report):
#     positives = vt_report.get('positives', 0)
#     total = vt_report.get('total', 0)
#     scans = vt_report.get('scans', {})

#     detected_count = sum(1 for scan in scans.values() if scan['detected'])
#     undetected_count = total - detected_count

#     # Prepare data for the bar plot
#     data = {
#         'Total Scans': total,
#         'Positives': positives,
#         'Detected': detected_count,
#         'Undetected': undetected_count
#     }

#     df = pd.DataFrame(list(data.items()), columns=['Category', 'Count'])

#     # Create bar plot
#     plt.figure(figsize=(10, 6))
#     plt.bar(df['Category'], df['Count'], color=['blue', 'red', 'green', 'orange'])
#     plt.xlabel('Category')
#     plt.ylabel('Count')
#     plt.title('VirusTotal Scan Results')
#     plt.tight_layout()

#     return plt
def plot_virustotal_data(vt_report):
    positives = vt_report.get('positives', 0)
    total = vt_report.get('total', 0)
    scans = vt_report.get('scans', {})

    detected_count = sum(1 for scan in scans.values() if scan['detected'])
    undetected_count = total - detected_count

    # Prepare data for the pie chart
    labels = ['Detected', 'Undetected']
    sizes = [detected_count, undetected_count]
    colors = ['red', 'green']
    explode = (0.1, 0)  # explode the first slice (Detected)

    # Create pie chart
    plt.figure(figsize=(10, 6))
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=140)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title('VirusTotal Scan Results')

    return plt