from Database import store_vulnerabilities, update_vulnerabilities
from NISTFetch import fetch_nist_vulnerabilities
from preprocess import filter_java_vulnerabilities
from dotenv import load_dotenv # type: ignore
import os

load_dotenv()

URL = os.getenv('URL')

def main():
    """
    Main function to fetch, filter, and store NIST vulnerability data.

    This function performs the following steps:
    1. Fetches NIST vulnerabilities from a specified URL.
    2. Filters the fetched data to include only Java vulnerabilities.
    3. Prints the number of Java vulnerabilities found.
    4. Stores the filtered Java vulnerabilities in the database.
    5. (Optional) Updates the database with the filtered Java vulnerabilities.

    Returns:
        str: A message indicating the completion of the data migration process.
    """
    nist_data = fetch_nist_vulnerabilities(URL)
    java_vulnerabilities = filter_java_vulnerabilities(nist_data)
    print(len(java_vulnerabilities))
    store_vulnerabilities(java_vulnerabilities)
    # update_vulnerabilities(java_vulnerabilities)
    return 'DATA MIGRATION COMPLETED'

if __name__ == '__main__':
    print(main())