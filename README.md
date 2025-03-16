# CryptoLens 🚀

**CryptoLens** is an automated tool for extracting, analyzing, and auditing SSL/TLS traffic. It maps cryptographic data from PCAP files to generate a comprehensive inventory of encryption methods, facilitating security assessments, compliance audits, and vulnerability analysis.

## 🔍 Overview
CryptoLens Offline utilizes Zeek to parse PCAP files, extract SSL/TLS logs, and enrich them with cipher suite metadata. The results are automatically compiled into an easy-to-read CSV report, helping security teams analyze cryptographic configurations effectively.

## ✨ Key Features
- PCAP-based Analysis: No need for external dependencies—analyze network traffic directly.
- Automated SSL/TLS Inspection: Extracts essential security details from captured traffic.
- Cipher Suite Mapping: Matches extracted data with industry-standard cipher suite definitions.
- Comprehensive Reports: Outputs security insights in CSV format for further analysis.
- Customizable & Extensible: Easily integrate with your security workflows.

## ⚙ Prerequisites
Before running CryptoLens, ensure your system meets the following requirements:

**1️⃣ [Docker](https://www.docker.com/)**
- Install Docker and ensure it is running.
- [Installation Guide](https://docs.docker.com/get-docker/)
  
**2️⃣ [MaxMind GeoLite2 Databases](https://dev.maxmind.com/geoip/)** (for ISP & location info)
- Download the following files and place them in the data/ISP_Database/ directory:
  - GeoLite2-ASN.mmdb
  - GeoLite2-City.mmdb

**3️⃣ System Permissions**
- The user must have root or sudo privileges.

## 🚀 Quick Start

**1️⃣ Navigate to the Project Root Directory**
```bash
cd crypto-lens-offline
```

**2️⃣ Configure .env File** (Set Paths for Logs & Cipher Data)

 | **Variable** | **Description**                             | **Default**                                 | **Required** |
   |--------------|---------------------------------------------|---------------------------------------------|--------------|
   | LOG_PATH   | Output path of logs extracted by zeek       | ./log_output                              | Yes❗         |
   | CS_FILE    | File path of ciphersuite data                | ./data/cipher_suites.json                 | Yes❗         |
   | ISP_ASN    | File path of ISP database (ASN)              | ./data/ISP_Database/GeoLite2-ASN.mmdb       | Yes❗         |
   | ISP_CITY   | File path of ISP database (city and country) | ./data/ISP_Database/GeoLite2-City.mmdb      | Yes❗         |

**3️⃣ Put your pcap files under `./pcap_files/` dir (create the folder under the project's root directory)**

**4️⃣ Run the Analysis**
```bash
sudo bash crypto_inventory.sh
```

**5️⃣ View the Reports**
- Processed reports are saved in: `output/crypto_inventory_report/`
- Example: `output/crypto_inventory_report/inventory_report_2024-10-18.csv`

## 📂 Project Structure
```plaintext
crypto-lens-offline/
├── README.md                 # Documentation
├── crypto_inventory.py        # Main script for data processing
├── crypto_inventory.sh        # Shell script for execution
├── data/                      # Supporting databases
│   ├── ISP_Database/          # ISP & location data
│   │   ├── GeoLite2-ASN.mmdb
│   │   ├── GeoLite2-City.mmdb
│   ├── cipher_suites.json     # Cipher suite metadata
├── log_output/                # Extracted Zeek logs
│   ├── <timestamp>/
│   │   ├── ssl.log            # TLS-related logs
│   │   ├── x509.log           # Certificate logs
│   │   ├── other Zeek logs...
├── output/
│   ├── crypto_inventory_report/  # Generated CSV reports
│   ├── logs/                    # Execution logs & errors
├── pcap_files/                 # Directory for input PCAP files
│   ├── sample.pcap              # Example network capture
├── zeek_analysis.sh            # Zeek automation script
└── requirements.txt            # Dependencies list
```

## 📊 Output Format
The generated report contains detailed security insights with the following structure:

| Field                       | Description                                     |
|-----------------------------|-------------------------------------------------|
| time                        | Timestamp of the connection                    |
| origin_ip                   | Source IP address                              |
| response_ip                 | Destination IP address                         |
| response_port               | Destination port (usually 443 for TLS)        |
| isp                         | Internet Service Provider                      |
| country                     | Geolocation (Country)                          |
| city                        | Geolocation (City)                             |
| cipher_suite_name           | Cipher suite identifier                        |
| cipher_suite_security       | Security level (e.g., secure, weak)           |
| cipher_suite_attribute_hex_code | Hexadecimal representation of cipher suite attributes |
| cipher_suite_attribute_tls_version | TLS versions supported by the cipher suite |
| cipher_suite_attribute_dec_code | Decimal representation of cipher suite attributes |
| cipher_suite_crypto_system_protocol_tag | Protocol tag for the cipher suite |
| cipher_suite_crypto_system_protocol_method | Method used in the cipher suite |
| cipher_suite_crypto_system_protocol_weakness | Known weaknesses of the protocol |
| cipher_suite_crypto_system_keyexchange_tag | Key exchange method tag |
| cipher_suite_crypto_system_keyexchange_method | Key exchange method used |
| cipher_suite_crypto_system_keyexchange_weakness | Known weaknesses of the key exchange method |
| cipher_suite_crypto_system_authentication_tag | Authentication method tag |
| cipher_suite_crypto_system_authentication_method | Authentication method used |
| cipher_suite_crypto_system_authentication_weakness | Known weaknesses of the authentication method |
| cipher_suite_crypto_system_encryption_tag | Encryption method tag |
| cipher_suite_crypto_system_encryption_method | Encryption method used |
| cipher_suite_crypto_system_encryption_weakness | Known weaknesses of the encryption method |
| cipher_suite_crypto_system_hash_tag | Hash method tag |
| cipher_suite_crypto_system_hash_method | Hash method used |
| cipher_suite_crypto_system_hash_weakness | Known weaknesses of the hash method |
| cipher_suite_reference_name | RFC reference (e.g., RFC 8446)                 |
| cipher_suite_reference_url  | URL to official documentation                 |

<details>
  <summary><i><strong style="display:inline-block">Example: </strong></i></summary>
  
|time               |origin_ip    |response_ip   |response_port|isp                              |country      |city  |tls_version|cipher_suite_name     |cipher_suite_security|cipher_suite_attribute_hex_code|cipher_suite_attribute_tls_version|cipher_suite_attribute_dec_code|cipher_suite_crypto_system_protocol_tag|cipher_suite_crypto_system_protocol_method|cipher_suite_crypto_system_protocol_weakness|cipher_suite_crypto_system_keyexchange_tag|cipher_suite_crypto_system_keyexchange_method|cipher_suite_crypto_system_keyexchange_weakness|cipher_suite_crypto_system_authentication_tag|cipher_suite_crypto_system_authentication_method|cipher_suite_crypto_system_authentication_weakness|cipher_suite_crypto_system_encryption_tag|cipher_suite_crypto_system_encryption_method                                     |cipher_suite_crypto_system_encryption_weakness|cipher_suite_crypto_system_hash_tag|cipher_suite_crypto_system_hash_method|cipher_suite_crypto_system_hash_weakness|cipher_suite_reference_name|cipher_suite_reference_url        |
|-------------------|-------------|--------------|-------------|---------------------------------|-------------|------|-----------|----------------------|---------------------|-------------------------------|----------------------------------|-------------------------------|---------------------------------------|------------------------------------------|--------------------------------------------|------------------------------------------|---------------------------------------------|-----------------------------------------------|---------------------------------------------|------------------------------------------------|--------------------------------------------------|-----------------------------------------|---------------------------------------------------------------------------------|----------------------------------------------|-----------------------------------|--------------------------------------|----------------------------------------|---------------------------|----------------------------------|
|2024/09/25-09:41:43|140.92.164.42|61.216.83.41  |443          |Data Communication Business Group|Taiwan       |Taipei|TLSv13     |TLS_AES_128_GCM_SHA256|recommended          |['0x13', '0x01']               |['TLS1.3']                        |4865                           |null                                   |Transport Layer Security (TLS)            |null                                        |PFS                                       |null                                         |null                                           |null                                         |null                                            |null                                              |AEAD                                     |Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)|null                                          |null                               |Secure Hash Algorithm 256 (SHA256)    |null                                    |RFC 8446                   |https://ciphersuite.info/rfc/8446/|
|2024/09/25-09:42:03|140.92.164.42|61.216.83.39  |443          |Data Communication Business Group|Taiwan       |Taipei|TLSv13     |TLS_AES_128_GCM_SHA256|recommended          |['0x13', '0x01']               |['TLS1.3']                        |4865                           |null                                   |Transport Layer Security (TLS)            |null                                        |PFS                                       |null                                         |null                                           |null                                         |null                                            |null                                              |AEAD                                     |Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)|null                                          |null                               |Secure Hash Algorithm 256 (SHA256)    |null                                    |RFC 8446                   |https://ciphersuite.info/rfc/8446/|
|2024/09/25-09:41:44|140.92.164.42|172.217.163.35|443          |GOOGLE                           |United States|null  |TLSv13     |TLS_AES_128_GCM_SHA256|recommended          |['0x13', '0x01']               |['TLS1.3']                        |4865                           |null                                   |Transport Layer Security (TLS)            |null                                        |PFS                                       |null                                         |null                                           |null                                         |null                                            |null                                              |AEAD                                     |Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)|null                                          |null                               |Secure Hash Algorithm 256 (SHA256)    |null                                    |RFC 8446                   |https://ciphersuite.info/rfc/8446/|
|2024/09/25-09:41:44|140.92.164.42|104.17.25.14  |443          |CLOUDFLARENET                    |null         |null  |TLSv13     |TLS_AES_128_GCM_SHA256|recommended          |['0x13', '0x01']               |['TLS1.3']                        |4865                           |null                                   |Transport Layer Security (TLS)            |null                                        |PFS                                       |null                                         |null                                           |null                                         |null                                            |null                                              |AEAD                                     |Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)|null                                          |null                               |Secure Hash Algorithm 256 (SHA256)    |null                                    |RFC 8446                   |https://ciphersuite.info/rfc/8446/|
|2024/09/25-09:41:44|140.92.164.42|142.251.8.95  |443          |GOOGLE                           |United States|null  |TLSv13     |TLS_AES_128_GCM_SHA256|recommended          |['0x13', '0x01']               |['TLS1.3']                        |4865                           |null                                   |Transport Layer Security (TLS)            |null                                        |PFS                                       |null                                         |null                                           |null                                         |null                                            |null                                              |AEAD                                     |Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)|null                                          |null                               |Secure Hash Algorithm 256 (SHA256)    |null                                    |RFC 8446                   |https://ciphersuite.info/rfc/8446/|

</details>

## 🔗 Additional Resources
- Zeek Documentation: https://zeek.org/documentation/
- Cipher Suite Reference: https://ciphersuite.info/
- MaxMind GeoIP: https://dev.maxmind.com/geoip/

## 📌 Future Enhancements
- Support for **Hybrid Mode** (PCAP + OpenSearch integration)
- Enhanced **TLS Vulnerability Analysis**
- GUI-based **Security Dashboard**