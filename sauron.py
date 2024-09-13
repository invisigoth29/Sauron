import requests
import yaml
import dns.resolver

# Load API keys from config file
def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)

config = load_config()

# Function to display your custom ASCII art banner
def display_banner():
    # Corrected ASCII art for "Sauron" with no eyeball image
    sauron_art = colored('''
  
__, , _ __,    _, __,    _,  _, _,_ __,  _, _, _
|_  \ | |_    / \ |_    (_  /_\ | | |_) / \ |\ |
|    \| |     \ / |     , ) | | | | | \ \ / | \|
~~~   ) ~~~    ~  ~      ~  ~ ~ `~' ~ ~  ~  ~  ~
     ~'
    ''', 'green') + colored('''
           Welcome to the Eye of Sauron - Gathering Intelligence
    ''', 'yellow', attrs=['bold'])

    print(sauron_art)

# Function to query Shodan
def shodan_lookup(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={config['shodan_api_key']}"
    response = requests.get(url)
    return response.json()

# Function to query FOFA
def fofa_lookup(ip):
    base64_query = f"ip={ip}".encode('utf-8').hex()  # FOFA requires base64 query
    url = f"https://fofa.so/api/v1/search/all?email={config['fofa_email']}&key={config['fofa_api_key']}&qbase64={base64_query}"
    response = requests.get(url)
    return response.json()

# Function to query IPinfo
def ipinfo_lookup(ip):
    url = f"https://ipinfo.io/{ip}?token={config['ipinfo_token']}"
    response = requests.get(url)
    return response.json()

# Function to query VirusTotal
def virustotal_lookup(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": config['virustotal_api_key']}
    response = requests.get(url, headers=headers)
    return response.json()

# Function for DNS lookups using 1.1.1.1 resolver
def dns_lookup(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['1.1.1.1']  # Cloudflare DNS

    record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'AAAA']
    dns_results = {}

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            dns_results[record_type] = [str(answer) for answer in answers]
        except dns.resolver.NoAnswer:
            dns_results[record_type] = f"No {record_type} record found."
        except dns.resolver.NXDOMAIN:
            dns_results[record_type] = "Domain does not exist."
        except dns.exception.DNSException as e:
            dns_results[record_type] = f"Error: {str(e)}"

    return dns_results

# Function to perform all lookups
def perform_lookup(ip_or_domain):
    display_banner()  # Show your custom ASCII art
    print(f"Performing lookups for {ip_or_domain}...\n")
    
    # DNS Lookup
    dns_data = dns_lookup(ip_or_domain)
    print("\n[DNS Lookup Results]")
    for record_type, records in dns_data.items():
        print(f"{record_type} records: {records}")

    # Shodan Lookup
    shodan_data = shodan_lookup(ip_or_domain)
    print("\n[Shodan Results]")
    print(shodan_data)

    # FOFA Lookup
    fofa_data = fofa_lookup(ip_or_domain)
    print("\n[FOFA Results]")
    print(fofa_data)

    # IPinfo Lookup
    ipinfo_data = ipinfo_lookup(ip_or_domain)
    print("\n[IPinfo Results]")
    print(ipinfo_data)

    # VirusTotal Lookup
    virustotal_data = virustotal_lookup(ip_or_domain)
    print("\n[VirusTotal Results]")
    print(virustotal_data)

# Main Execution
if __name__ == "__main__":
    ip_or_domain = input("Enter an IP address or domain name to lookup: ")
    perform_lookup(ip_or_domain)
