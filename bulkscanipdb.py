# ==============================================
# IPs will be checked with AbuseIPDB API and exported to an Excel file
# Modified to exclude private IPs and handle duplicates
# ==============================================
from datetime import datetime
from decouple import config
import requests
import json
import xlsxwriter
import re
import os
import ipaddress

abuseipdb_apikey = config('ABUSEIPDB_APIKEY')
prefile = r'ips.csv'
file = prefile.encode('unicode-escape').decode()
path = os.path.dirname(os.path.abspath(file))
print(path)

# Use a set to automatically handle unique IPs
unique_ips = set()
result_list = []

def update_result_list(response_json):
    # Check if this IP's result hasn't been added yet
    ip = response_json["data"]["ipAddress"]
    if ip not in [entry[0] for entry in result_list]:
        result_list.append([
            str(ip),
            str(response_json["data"]["domain"]),
            str(response_json["data"]["hostnames"]),
            str(response_json["data"]["abuseConfidenceScore"]),
            str(response_json["data"]["totalReports"]),
            str(response_json["data"]["countryCode"]),
            str(response_json["data"]["isp"]),
            str(response_json["data"]["usageType"]),
            str(response_json["data"]["lastReportedAt"])
        ])

def write_to_excel():
    now = datetime.now()
    dt_string = now.strftime("%d%m%Y-%H%M%S")
    filename = 'abuseipdb_export-' + dt_string + '.xlsx'
    workbook = xlsxwriter.Workbook(os.path.join(path, filename))
    worksheet = workbook.add_worksheet()
    bold = workbook.add_format({'bold': True})

    worksheet.set_column('A:I', 20)
    worksheet.write('A1', 'IP', bold)
    worksheet.write('B1', 'Domain', bold)
    worksheet.write('C1', 'Hostnames', bold)
    worksheet.write('D1', 'Abuse confidence in %', bold)
    worksheet.write('E1', 'Number of reports', bold)
    worksheet.write('F1', 'Country', bold)
    worksheet.write('G1', 'ISP', bold)
    worksheet.write('H1', 'Type', bold)
    worksheet.write('I1', 'Last reported', bold)

    for row, data in enumerate(result_list, start=1):
        for col, value in enumerate(data):
            worksheet.write(row, col, value)

    print(f"File saved at: \n{os.path.join(path, filename)}")
    workbook.close()

def do_request(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_apikey
    }
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    response = requests.get(url=url, headers=headers, params=querystring)
    response_json = json.loads(response.text)
    update_result_list(response_json)

def extract_ips_from_file(file):
    with open(file, 'r') as f:
        content = f.read()

    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    private_networks = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('0.0.0.0/32')
    ]

    for match in pattern.findall(content):
        try:
            ip = ipaddress.ip_address(match)
            if not any(ip in net for net in private_networks) and match not in unique_ips:
                unique_ips.add(match)
                do_request(match)
        except ValueError:
            continue

if __name__ == "__main__":
    extract_ips_from_file(file)
    write_to_excel()