from dotenv import load_dotenv 
import requests
import os
import hashlib
import base64

# Load environment variables
load_dotenv()
api_key = os.getenv("VT_API_KEY")

# Display ASCII banner
def ascii_banner():
    print(r"""                    
 _   _ _ __| |  ___  ___ __ _ _ __  _ __   ___ _ __ 
| | | | '__| | / __|/ __/ _` | '_ \| '_ \ / _ \ '__|
| |_| | |  | | \__ \ (_| (_| | | | | | | |  __/ |   
 \__,_|_|  |_| |___/\___\__,_|_| |_|_| |_|\___  |_|
""")

# Displays menu options
def show_menu():
    print("Menu Options:")
    print("1. URL")
    print("2. File")
    print("3. Exit")
    print("")

# Scan URL with VirusTotal API
def scan_url_virustotal(url):
    try:
        # Encode URL to get the URL ID (base64url of SHA-256)
        url_hash = hashlib.sha256(url.encode()).digest()
        url_id = base64.urlsafe_b64encode(url_hash).decode().rstrip('=')
        
        # Make API request to VirusTotal
        headers = {"x-apikey": api_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            analysis = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            # Count detections
            malicious = analysis.get("malicious", 0)
            suspicious = analysis.get("suspicious", 0)
            undetected = analysis.get("undetected", 0)
            
            # Determine status based on vendor detections
            if malicious > 0:
                status = "Malicious"
            elif suspicious > 0:
                status = "Suspicious"
            else:
                status = "Secure"
            
            return status, malicious, suspicious, undetected
        elif response.status_code == 404:
            return "Not yet scanned", 0, 0, 0
        else:
            return "Error scanning URL", 0, 0, 0
    except Exception as e:
        print(f"Error: {e}")
        return "Error", 0, 0, 0

# Diagnose URL protocol
def diagnose_url_protocol(url):
    # Determine protocol
    if url.lower().startswith("https"):
        protocol = "HTTPS"
    elif url.lower().startswith("http"):
        protocol = "HTTP"
    else:
        print("Unknown Protocol\n")
        return
    
    print(f"Protocol: {protocol}\n")
    
    # Scan with VirusTotal
    print("Scanning URL with VirusTotal...")
    status, malicious, suspicious, undetected = scan_url_virustotal(url)
    print(f"Results: {status}")
    print(f"Detections: {malicious} malicious, {suspicious} suspicious, {undetected} undetected\n")
    
    print("Would you like to scan another URL? (y/n)")
    another = input().strip().lower()
    if another == 'y':
        handle_url_scan()
    else:
        ascii_banner()
        show_menu()

# Handle URL scan option
def handle_url_scan():
    url = input("Enter URL: ").strip()
    diagnose_url_protocol(url)

# Handle file scan option
def handle_file_scan():
    file = input("Enter file: ").strip()
    

# Get menu choice from user
def get_user_choice():
    while True:
        choice = input("Choose an option (1-3): ").strip()
        if choice not in ['1', '2', '3']:
            print("Invalid choice. Please enter 1, 2, or 3.")
        else:
            if choice == '1':
                handle_url_scan()
            elif choice == '2':
                handle_file_scan()
            elif choice == '3':
                print("Exiting program.\n")
                break
        
# Display
ascii_banner()
show_menu()
get_user_choice()
