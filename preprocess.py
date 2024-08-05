from datetime import datetime

def filter_java_vulnerabilities(nist_data):
    """
    Filter NIST vulnerabilities data to include only Java-related vulnerabilities within a specific date range.

    This function processes the NIST vulnerabilities data to extract Java vulnerabilities, excluding those related to JavaScript.
    It filters the vulnerabilities based on their published date, ensuring they fall within the range from January 1, 2023, to December 31, 2024.

    Args:
        nist_data (dict): The NIST vulnerabilities data in JSON format. This should include:
            - 'CVE_Items': A list of CVE items, each containing information such as:
                - 'publishedDate': The date when the vulnerability was published.
                - 'cve': A dictionary with 'description' containing 'description_data'.
                - 'configurations': Configuration data related to the vulnerability.

    Returns:
        list: A list of dictionaries representing Java vulnerabilities that match the criteria. Each dictionary contains:
            - 'cve_id': The CVE identifier of the vulnerability.
            - 'package_name': The package name, set to 'Java' for all entries.
            - 'description': A description of the vulnerability.
            - 'vulnerable_versions': Versions affected by the vulnerability, or an empty string if not available.
            - 'published_date': The published date of the vulnerability in ISO 8601 format.
            - 'created_date': The date when the entry was created, in ISO 8601 format.
            - 'created_by': The creator of the entry, set to 'admin'.

    Notes:
        - The function prints warnings for any issues encountered with the data format or date parsing.
        - Only vulnerabilities with descriptions containing 'java' and not 'javascript' are included.
        - If the 'CVE_Items' field is missing or is not a list, an empty list is returned.
    """
    java_vulnerabilities = []

    start_date = datetime.strptime('2023-01-01T00:00Z', '%Y-%m-%dT%H:%M%z')
    end_date = datetime.strptime('2024-12-31T23:59Z', '%Y-%m-%dT%H:%M%z')

    cve_items = nist_data.get('CVE_Items', [])
    if not isinstance(cve_items, list):
        print("CVE_Items is not a list or is missing.")
        return java_vulnerabilities

    for cve_data in cve_items:
        published_date_str = cve_data.get('publishedDate', '')
        if not published_date_str:
            print(f"Missing or empty publishedDate for item: {cve_data.get('cve', {}).get('CVE_data_meta', {}).get('ID')}")
            continue
        
        try:
            published_date = datetime.strptime(published_date_str, '%Y-%m-%dT%H:%M%z')
        except ValueError:
            print(f"Date parsing failed for: {published_date_str}")
            continue

        if start_date <= published_date <= end_date:
            description_data = cve_data.get('cve', {}).get('description', {}).get('description_data', [])
            if not isinstance(description_data, list):
                print(f"Invalid description_data format for item: {cve_data.get('cve', {}).get('CVE_data_meta', {}).get('ID')}")
                continue

            for description in description_data:
                description_value = description.get('value', '').lower()
                if 'java' in description_value and 'javascript' not in description_value:
                    java_vulnerabilities.append({
                        'cve_id': cve_data.get('cve', {}).get('CVE_data_meta', {}).get('ID'),
                        'package_name': 'Java',
                        'description': description_value,
                        'vulnerable_versions': cve_data.get('configurations', {}).get('CVE_version_data', ''),
                        'published_date': published_date_str,
                        'created_date': datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
                        'created_by': 'admin'
                    })
    
    return java_vulnerabilities

