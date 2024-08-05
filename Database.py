import os
from pymongo import MongoClient
from dotenv import load_dotenv # type: ignore
from datetime import datetime

load_dotenv()

DB_HOST = os.getenv('DB_HOST')
DB_PORT = int(os.getenv('DB_PORT'))
DB_NAME = os.getenv('DB_NAME')
DB_COLLECTION = os.getenv('DB_COLLECTION')


try:
    client = MongoClient(DB_HOST, DB_PORT)
    db = client[DB_NAME]
    vulnerabilities_collection = db[DB_COLLECTION]
    print("Connected to MongoDB")
except Exception as e:
    print(f"An error occurred while connecting to MongoDB: {e}")
    raise

def store_vulnerabilities(vulnerabilities):
    """
    Store a list of vulnerabilities in the MongoDB collection.

    Each vulnerability is upserted based on its 'cve_id'. If a document with the
    same 'cve_id' exists, it will be updated; otherwise, a new document will be created.

    Args:
        vulnerabilities (list): A list of dictionaries, each containing details about a vulnerability.
            Each dictionary should have the following structure:
            {
                'cve_id': str,                   # The CVE identifier for the vulnerability.
                'package_name': str,             # The name of the affected package.
                'vulnerable_versions': list,     # A list of versions that are vulnerable.
                'description': str,              # A description of the vulnerability (optional).
                'published_date': str,           # The date the vulnerability was published (optional).
                'created_date': datetime,        # The date the vulnerability was created (optional, default is current UTC time).
                'created_by': str                # The identifier for who created the record (optional, default is 'unknown').
            }
    """
    for vuln in vulnerabilities:
        vulnerabilities_collection.update_one(
            {'cve_id': vuln['cve_id']},
            {
                '$set': {
                    'package_name': vuln['package_name'],
                    'vulnerable_versions': vuln['vulnerable_versions'],
                    'description': vuln.get('description', ''),
                    'published_date': vuln.get('published_date', ''),
                    'created_date': vuln.get('created_date', datetime.utcnow()),
                    'created_by': vuln.get('created_by', 'unknown')
                }
            },
            upsert=True
        )

def update_vulnerabilities(vulnerabilities):
    """
    Update a list of vulnerabilities in the MongoDB collection.

    Each vulnerability is upserted based on its 'cve_id'. If a document with the
    same 'cve_id' exists, it will be updated; otherwise, a new document will be created.

    Args:
        vulnerabilities (list): A list of dictionaries, each containing details about a vulnerability.
            Each dictionary should have the following structure:
            {
                'cve_id': str,                   # The CVE identifier for the vulnerability.
                'package_name': str,             # The name of the affected package.
                'vulnerable_versions': list,     # A list of versions that are vulnerable.
                'description': str,              # A description of the vulnerability (optional).
                'published_date': str,           # The date the vulnerability was published (optional).
                'created_date': datetime,        # The date the vulnerability was created (optional, default is current UTC time).
                'created_by': str                # The identifier for who created the record (optional, default is 'unknown').
            }
    """
    for vuln in vulnerabilities:
        vulnerabilities_collection.update_one(
            {'cve_id': vuln['cve_id']},
            {
                '$set': {
                    'package_name': vuln['package_name'],
                    'vulnerable_versions': vuln['vulnerable_versions'],
                    'description': vuln.get('description', ''),
                    'published_date': vuln.get('published_date', ''),
                    'created_date': vuln.get('created_date', datetime.utcnow()),
                    'created_by': vuln.get('created_by', 'unknown')
                }
            },
            upsert=True
        )
