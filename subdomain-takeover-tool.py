# Built-in libraries
import sys
import asyncio

# Requires install
try:
    import dns.rdata
    import dns.resolver
    import dns.zone
    import dns.rdatatype
    import aiohttp
    from colorama import Fore, Back, Style
except:
    print(f"\nThis subdomain takeover tool requires additional Python libraries to be installed.\n"
          f"Please create a Python virtual environment and install the additional libraries with the following commands:\n"
          f"\t python3 -m venv .venv\n"
          f"\t source .venv/bin/activate\n"
          f"\t pip install aiohttp dnspython colorama\n\n"
          f"You can exit from the Python environment using the 'deactivate' command.\n")
    exit()

STR_IDNT_1 = " - "

STR_URL_GITHUB = "www.github.com"
STR_URL_GITHUB_PAGES = "github.io"
# List of Azure service domains are available at: https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-domains
STR_URL_AZURE_FILES = "file.core.windows.net"

######################################################################
## PRE-RUN CHECK FUNCTIONS
#########################

def check_arguments(arguments):
    if len(arguments) < 2:
        print_usage(arguments[0])
        exit()

# Check that entered subdomain is valid based on number of '.'
def check_subdomain_valid(subdomain):
    if subdomain.count('.') < 2:
        print(f"{subdomain} is not a valid subdomain.")
        return False

    return True

# Check that the subdomain is of CNAME type and accessible
def check_type_cname(subdomain):
    try:
        answer = str(dns.resolver.resolve(subdomain, dns.rdatatype.CNAME)[0])[:-1]
        return answer
    except:
        print(f"Record for subdomain {subdomain} does not exist or is not of CNAME type.")
        print(f"If you believe this is an error, please check your internet connection. An internet connection is required to test subdomains.")
        return False

######################################################################
## PLATFORM-SPECIFIC CNAME ANSWER CHECKS
##
## Notes:
## - "return True" means that it IS VULNERABLE
#########################

##########
# Generic (Unsupported platforms)

# Check that the answer for the CNAME does not exist exist
async def check_vulnerable_generic(answer):
    try:
        dns.resolver.resolve(answer, dns.rdatatype.ANY)
    except:
        print_domain_does_not_exist(answer)
        return True

    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://{answer}") as response:
            if response.status == 404:
                print(STR_IDNT_1 + f"Target domain {answer} was accessible, but not found (404 returned)")
                return True
            else:
                print(Fore.GREEN + STR_IDNT_1 + f"Target domain {answer} exists" + Style.RESET_ALL)
                return False

##########
# GitHub Pages

# Check that the GitHub subdomain does not exist
async def check_vulnerable_github_pages(github_subdomain):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://{github_subdomain}") as response:
            if response.status == 404:
                print(Fore.RED + STR_IDNT_1 + f"GitHub Pages website at {github_subdomain} not found (404 returned)" + Style.RESET_ALL)
                return True
            else:
                print(Fore.GREEN + STR_IDNT_1 + f"GitHub Pages website exists at {github_subdomain}" + Style.RESET_ALL)
                return False

# Check that the GitHub profile with the username does not exist
async def check_vulnerable_github_account(github_username):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://{STR_URL_GITHUB}/{github_username}") as response:
            if response.status == 404:
                print(Fore.RED + STR_IDNT_1 + f"GitHub profile with username {github_username} not found (404 returned)" + Style.RESET_ALL)
                return True
            else:
                print(Fore.GREEN + STR_IDNT_1 + f"GitHub profile with username {github_username} exists" + Style.RESET_ALL)
                return False

##########
# Azure Files

# Check that Azure Files Subdomain does not exist
# Notes:
# - Azure only creates a dedicated subdomain for active services
# - Services which were deleted or never created do not have a subdomain record on the domain
async def check_vulnerable_azure_files(answer):
    try:
        dns.resolver.resolve(answer, dns.rdatatype.ANY)
        print(Fore.GREEN + STR_IDNT_1 + f"Target domain {answer} exists" + Style.RESET_ALL)
        return False
    except:
        print_domain_does_not_exist(answer)
        return True        

######################################################################
## PRINT FUNCTIONS
#########################

def print_usage(filename):
    print(f"\nUsage: python3 {filename} <subdomain>\n"
          f"  or : python3 {filename} -f <zone-file-name> <root-domain>\n"
          f"       example: python3 {filename} -f domain.zone example.com\n"
          f"\nZone file must be in BIND-compatible format\n")

def print_domain_does_not_exist(domain):
    print(STR_IDNT_1 + f"Target domain {domain} does not exist")

def print_not_vulnerable(subdomain):
    print(Back.GREEN + f"{subdomain} is not vulnerable to a subdomain takeover attack." + Style.RESET_ALL + "\n\n")

def print_vulnerable(subdomain):
    print(Back.RED + f"{subdomain} is likely VULNERABLE to a subdomain takeover attack! URGENT ACTION IS RECOMMENDED!" + Style.RESET_ALL + "\n\n")

######################################################################
## ZONE FILE PARSING
#########################

def parse_dns_zone_file(filepath, root_domain):
    subdomains = []
    zone = dns.zone.from_file(filepath, root_domain)
    for name, node in zone.nodes.items():
        for rdataset in node.rdatasets:
            if rdataset.rdtype == dns.rdatatype.CNAME:
                subdomain = name.to_text() + '.' + root_domain
                subdomains.append(subdomain)

    return subdomains

######################################################################
## MAIN FUNCTIONS
#########################

# Check all subdomains in the list
def check_subdomains(subdomains):
    for subdomain in subdomains:
        if check_subdomain_valid(subdomain) == False:
            continue

        answer = check_type_cname(subdomain)

        if answer == False:
            print(f"\n")
            continue
        else:
            print(f"Analysing subdomain {subdomain}...")

        if answer.endswith(STR_URL_GITHUB_PAGES):
            print(f" - Subdomain points to a GitHub Pages website at {answer}")
            
            if asyncio.run(check_vulnerable_github_pages(answer)) == False:
                print_not_vulnerable(subdomain)
                continue

            github_username = answer.split(".")[0]
            if asyncio.run(check_vulnerable_github_account(github_username)) == False:
                print_not_vulnerable(subdomain)
                continue

            print_vulnerable(subdomain)

        elif answer.endswith(STR_URL_AZURE_FILES):
            print(f" - Subdomain points to a Azure Files service at {answer}")
            
            if asyncio.run(check_vulnerable_azure_files(answer)) == False:
                print_not_vulnerable(subdomain)
                continue
            print_vulnerable(subdomain)

        else:
            print(f" - Subdomain points to a service at {answer}, which currently cannot be accurately tested by this tool")
            if asyncio.run(check_vulnerable_generic(answer)) == False:
                print(f"{subdomain} is unlikely to be vulnerable to a subdomain takeover attack.\n\n")
                continue
            else:
                print(Back.YELLOW + f"{subdomain} may be vulnerable to a subdomain takeover attack. Please check that the service is still active."  + Style.RESET_ALL + "\n\n")

# Python Main
check_arguments(sys.argv) 

if sys.argv[1] == "-f":
    if len(sys.argv) != 4:
        print_usage(sys.argv[0])
        exit()
    
    check_subdomains(parse_dns_zone_file(sys.argv[2], sys.argv[3]))

else:
    check_subdomains(sys.argv[1:])
