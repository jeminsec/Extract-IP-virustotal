# Collect subdomain and IP from Virustotal

[Extract IP Virus Total](https://github.com/jeminsec/Extract-IP-virustotal) is a Bash automation tool that leverages the VirusTotal API v2 to fetch subdomains of a given root domain and extract their associated IP addresses.
The tool is designed for** bug bounty hunters, penetration testers, and researchers** who want to quickly collect infrastructure intelligence (subdomains + resolved IPs) in a structured and customizable way.

# Features
**🔑 Automatic API Key Handling**

Prompts for your VirusTotal API key on first run.
Saves it inside the script itself for future runs (so you don’t re-enter).

**🌐 Subdomain Enumeration**

Uses VirusTotal domain report to fetch all discovered subdomains.

**🗂️ Flexible Output Options**
Save all IPs in one master file (rootdomain_ip.txt).
Or create a folder (rootdomain-ip/) and save per-subdomain IP files (e.g., subdomain_ip.txt).

**🛡️ Safe Handling**

Cleans up temp files automatically.
Sanitizes filenames for OS compatibility.

**⏱️ Rate Limit Aware**

Adds a delay (default: 16s) between API calls to respect VirusTotal’s free tier limits.


## ⚙️ Requirements

- bash  
- curl    
- jq (https://github.com/jqlang/jq)  
- perl

**Install dependencies (Debian/Ubuntu):**  
``` sudo apt update && sudo apt install curl jq perl -y ```

## 🚀 Usage
### 1. Clone Repo and Make Executable
```
git clone https://github.com/jeminsec/Extract-IP-virustotal
cd Extract-IP-virustotal 
chmod +x Extract-IP-virustotal.sh
```

### 2. Run this script
```
./Extract-IP-virustotal.sh
```

> [!NOTE]
> On first run:  
> You’ll be asked for your VirusTotal API key [ Get it for free on [Virustotal](https://www.virustotal.com/) ]
> Key is stored inside the script for future use.

### 3. Provide Root Domain
```
Enter the target domain: (e.g., google.com)
```

### 4. Choose output style
You’ll be prompted:
```
How do you want to save IPs?
1) All IPs in a single file: google.com_ip.txt
2) Create folder google.com-ip/ with per-subdomain files
```
- Option 1 → Single file with all unique IPs.  
* Option 2 → Creates a folder and saves IPs per subdomain.

**📂 Example Outputs**  

**Option 1 (Single File)**
```
google.com_ip.txt → contains all unique IPs.
google.com_sub.txt → contains all subdomains.
```

**Option 2 (Per-Subdomain Files)**
```
google.com-ip/
 ├── www.google.com_ip.txt
 ├── api.google.com_ip.txt
 ├── drive.google.com_ip.txt
google.com_sub.txt

```

## ⚠️ Notes & Limitations
- Free VT API key allows only 4 requests/min → script enforces delay (default: 16s).  
* IP results depend on VirusTotal’s dataset, not live DNS.  
+ This tool is for educational & authorized security testing only.

### 🛠️ Customization

 **Change API delay:**
 ```
 DELAY=16
 ```
 **Reset stored API key by editing the script and replacing the line:**
 ```
 APIKEY="APIKEY_PLACEHOLDER"
 ```

## 📜 License
MIT License – free to use and modify.

## 🤝 Contributing
Pull requests and suggestions are welcome!
