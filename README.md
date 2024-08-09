# Documentation for Vulnerability Database Project

## 1. Introduction
   This project focuses on building and enriching a vulnerability database by analyzing NIST vulnerability feeds for 2023 and 2024. The goal is to filter and store Java-related vulnerabilities, ensuring that our database provides accurate and timely information to security engineers.

## 2. Setup and Installation

   - **Cloning the Repository**:
     ```bash
     git clone https://github.com/ramyaradjesh/Security-Database-Enrichment-.git
     cd vulnerability-database
     ```

   - **Setting Up the Virtual Environment**:
     ```bash
     python -m venv venv
     source venv/bin/activate  
     ```

   - **Installing Dependencies**:
     ```bash
     pip install -r requirements.txt
     ```

   - **Configuring Environment Variables**:
     Create a `.env` file with the necessary configuration:
     ```env
     DB_HOST=localhost
     DB_PORT=27017
     DB_NAME=vulnerability_db
     DB_COLLECTION=vulnerabilities
     URL=https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2023-2024.json.zip
     ```

## 3. Usage

   - **Running the Script**:
     ```bash
     python main.py
     ```
     This will fetch, filter, and store/update the Java-related vulnerabilities in the MongoDB database.

## 4. Code Explanation

   - **`fetch_nist_vulnerabilities(url)`**:
     - Description: Fetches and extracts data from a ZIP file at the given URL.
     - Parameters: `url` (str) - URL to fetch the NIST vulnerabilities data.
     - Returns: Data extracted from the JSON file inside the ZIP.

   - **`filter_java_vulnerabilities(nist_data)`**:
     - Description: Filters vulnerabilities to include only Java-related ones within a specified    date range.
     - Parameters: `nist_data` (dict) - NIST vulnerabilities data in JSON format.
     - Returns: List of Java vulnerabilities matching the criteria.

   - **`store_vulnerabilities(vulnerabilities)`**:
     - Description: Stores or updates vulnerabilities in the MongoDB collection.
     - Parameters: `vulnerabilities` (list) - List of vulnerabilities to be stored.

   - **`update_vulnerabilities(vulnerabilities)`**:
     - Description: Optionally updates existing vulnerabilities in the MongoDB collection.
     - Parameters: `vulnerabilities` (list) - List of vulnerabilities to be updated.

## 5. Rationale

   - **Python**: Opted for its simplicity and robust libraries for data handling.
   - **MongoDB**: Chosen for its schema flexibility and scalability.
   - **Requests Library**: Selected for its ease of HTTP requests.
   - **Datetime Library**: Used for accurate date comparisons and filtering.

## 6. AI Tools

   - All functionalities are based on conventional data processing techniques. 

## 7. References

   - [NIST Vulnerability Data](https://nvd.nist.gov/)
   - [OSV Database](https://osv.dev/)
