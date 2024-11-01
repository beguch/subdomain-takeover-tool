# Subdomain Takeover Tool

This tool allows you to ensure that your subdomains are not vulnerable to a subdomain attack. It examines the destination domains of your CNAME records, checking that the domains point to active services. Depending on the service it is pointing to, specific tests for the service's subdomain may be done to provide you with more accurate results. See the [Supported services](#supported-services) section to see a list of services which have tailored tests.

## Installation

This tool relies on external Python libraries, which can be installed by running the following commands.

```bash
# Create a Python virtual environment and switch to it.
python3 -m venv .venv
source .venv/bin/activate

# Install the external libraries with pip
pip install aiohttp dnspython colorama
```

## Usage

```bash
# Testing a single subdomain
python3 subdomain-takeover-tool.py <subdomain>
# Example:
python3 subdomain-takeover-tool.py example.example.com

# Testing multiple subdomains
python3 subdomain-takeover-tool.py <subdomain 1> <subdomain 2> <subdomain 3>
# Example:
python3 subdomain-takeover-tool.py example1.example.com example2.example.com example3.example.com

# Testing the entire domain with a DNS zone file
python3 subdomain-takeover-tool.py -f <DNS zone filename> <domain name>
# Example:
python3 subdomain-takeover-tool.py -f domain.zone example.com
```

## Supported services
The following services currently have specific tests to give accurate vulnerability status results.
* [GitHub Pages](https://pages.github.com/)
* [Azure Files](https://learn.microsoft.com/en-us/azure/storage/files/storage-files-introduction)