from requests.auth import HTTPBasicAuth
import urllib.parse
import linecache
import requests
import json
import sys

user = '<username>'
password = '<password>'
page_size = 500
portal_url = "<portal-url>" # e.g. "https://<name>-portal.asimily.com" 
api_endpoint = "/api/extapi/assets"
filename = "asset_export.json"

# Filter and Pagination parameters
params = { 'deviceType': ['Infusion pump','IoT/Medical device']}

url_pramas = urllib.parse.urlencode(params, quote_via=urllib.parse.quote, doseq=True)
base_url = "".join([portal_url, api_endpoint, "/?", url_pramas, '&size=', str(page_size)])

# Make get call to given endpoint
def make_api_call(user, password, url):
    data = {}
    try:
        response = requests.get(url, auth = HTTPBasicAuth(user,password))
        data = response.json()
    except Exception as e:
        print("Exception occured while fetching data for URL:", url)
        print('-'*50)
        print("Oops!", e.__class__, "occurred.")
        print('-'*50)
    
    return data

# Iterate through the API pages and export all assests matching filter criteria 
def asset_export(filename): 
    print("-"*50)
    print("Exporting asset data for site:", portal_url)
    print("Filters:")
    for k, v in params.items():
        print("\t",k ,":", v)
    print("-"*50)
    records = []
    data = {}
    data = make_api_call(user, password, base_url + '&page=0')
    
    if (bool(data)):
        # totalPages - In reponse, get node totalPages. 
        total_pages = int(data['totalPages'])
        records = data['content']
        
        # Loop over number of pages to get all devices matching the filter condition
        for page_num in range(1, total_pages):
            url = base_url + '&page='+ str(page_num)
            print("[info] fetching:", url)
            data = make_api_call(user, password, url)
            records = records + (data['content'])
        
        print("~"*90)
        print("Total records:", len(records))

        if(len(records) > 0):
            resultset = json.dumps(records, indent=4)
            
            # Writing to json file
            with open(filename, "w") as outfile:
                outfile.write(resultset)
            print("Sucessfully exported asset records to file:", filename)
            print("~"*90)
    else:
        print("~"*90)
        print("Please check :: Nothing to export")
        print("~"*90)

# Invoke method to export asset with specified filter criteria defined at the top
asset_export(filename)
