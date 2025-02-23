import re
import whois  
import tkinter as tk  
from tkinter import messagebox  
from urllib.parse import urlparse, unquote  
from datetime import datetime  
import socket  

# Function to check if a URL has suspicious keywords
def has_suspicious_keywords(url):
    suspicious_keywords = ['login', 'secure', 'account', 'banking', 'paypal', 'Paytm', 'update', 'verify']
    for word in suspicious_keywords:
        if word in url.lower():
            return True
    return False

# Function to check the length of the URL
def check_url_length(url):
    if len(url) > 75:  
        return True
    return False

# Function to check for misleading characters (e.g., xn-- in internationalized domains)
def check_misleading_characters(url):
    if "xn--" in url:  
        return True
    return False

# Function to check the domain registration date (newly registered domain can be suspicious)
def check_domain_reputation(url):
    try:
        domain_info = whois.whois(url)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date[0]
            if (datetime.now() - creation_date).days < 30:  
                return True
    except Exception as e:
        print(f"Error checking domain reputation: {e}")
    return False

# Function to check if the URL uses HTTPS
def check_https(url):
    if url.startswith("https://"):  
        return False  
    return True  

# Function to check TLD (Top-Level Domain) for suspicious ones (e.g., .xyz, .top, .club, often used by phishers)
def check_tld(url):
    suspicious_tlds = ['.xyz', '.top', '.club', '.info', '.party']  
    parsed_url = urlparse(url)
    if any(parsed_url.netloc.endswith(tld) for tld in suspicious_tlds):
        return True
    return False

# Function to check URL encoding (e.g., %20 for spaces), often used to hide phishing elements
def check_url_encoding(url):
    decoded_url = unquote(url)  
    if decoded_url != url:
        return True  
    return False

# Function to check if the URL has multiple subdomains (a common phishing tactic)
def check_multiple_subdomains(url):
    parsed_url = urlparse(url)
    subdomains = parsed_url.netloc.split('.')
    if len(subdomains) > 3:  
        return True
    return False

# Function to check for domain mismatches (e.g., typo-squatting or URL spoofing)
def check_domain_mismatch(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    try:
        
        main_domain = '.'.join(domain.split('.')[-2:])
        
        ip = socket.gethostbyname(domain)
        if main_domain not in domain:
            return True
    except socket.gaierror:
        return False
    return False

# Function to detect fake subdomains (e.g., `paypal.com.fake.site.com`)
def check_fake_subdomains(url):
    parsed_url = urlparse(url)
    subdomain = parsed_url.netloc.split('.')[0]  
    if 'paypal' in subdomain and 'paypal' not in parsed_url.netloc:
        return True  
    return False

# Main function to scan the URL and return results based on the checks
def scan_url(url):
    if has_suspicious_keywords(url):
        return "Suspicious: Contains suspicious keywords."
    if check_url_length(url):
        return "Suspicious: URL is too long."
    if check_misleading_characters(url):
        return "Suspicious: Contains misleading characters."
    if check_domain_reputation(url):
        return "Suspicious: Domain is newly registered."
    if check_https(url):
        return "Suspicious: No HTTPS, potential security risk."
    if check_tld(url):
        return "Suspicious: Domain uses a suspicious TLD."
    if check_url_encoding(url):
        return "Suspicious: URL is encoded, possibly hiding phishing details."
    if check_multiple_subdomains(url):
        return "Suspicious: URL contains multiple subdomains, potentially obfuscating the real domain."
    if check_domain_mismatch(url):
        return "Suspicious: Domain mismatch or typo-squatting detected."
    if check_fake_subdomains(url):
        return "Suspicious: Fake subdomain detected (e.g., paypal.com.fake.site.com)."
    
    return "Safe: URL looks normal."

# Function to handle user input in the GUI
def check_url_button_click():
    url = url_entry.get()  
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL.") 
        return
    
    result = scan_url(url)  # Scan the URL
    result_label.config(text=f"Result: {result}")  

# Set up the GUI window
window = tk.Tk()
window.title("Phishing Link Scanner")  
window.geometry("500x300")  

# Instruction label
instruction_label = tk.Label(window, text="Enter a URL to check if it is suspicious or safe:")
instruction_label.pack(pady=10)

# URL entry widget
url_entry = tk.Entry(window, width=50)
url_entry.pack(pady=10)

# Button to trigger URL scan
check_button = tk.Button(window, text="Check URL", command=check_url_button_click)
check_button.pack(pady=10)

# Label to display the scan result
result_label = tk.Label(window, text="Result: ", font=("Arial", 12, "bold"))
result_label.pack(pady=10)

# Start the GUI main loop
window.mainloop()
