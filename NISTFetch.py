import requests
import zipfile
import io
import json

def fetch_nist_vulnerabilities(url):
    """
    Fetch NIST vulnerabilities data from the specified URL.

    This function performs the following steps:
    1. Sends an HTTP GET request to the provided URL.
    2. Extracts a ZIP file from the response content.
    3. Reads the first JSON file found inside the ZIP file.
    4. Parses and returns the JSON data.

    Args:
        url (str): The URL to fetch the NIST vulnerabilities data from.

    Returns:
        dict or None: The parsed JSON data if successful, or None if an error occurs.

    Exceptions:
        - If there is an error with the HTTP request, it prints an error message and returns None.
        - If there is an error with the ZIP file, it prints an error message and returns None.
        - If there is an error decoding the JSON, it prints an error message and returns None.
    """    
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            json_filename = zip_file.namelist()[0]
            with zip_file.open(json_filename) as json_file:
                data = json.load(json_file)
                return data
        
    except requests.exceptions.RequestException as req_err:
        print(f"Request error occurred: {req_err}")
        return None
    except zipfile.BadZipFile as zip_err:
        print(f"Error with ZIP file: {zip_err}")
        return None
    except json.JSONDecodeError as json_err:
        print(f"Error decoding JSON: {json_err}")
        return None

