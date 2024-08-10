# IP Tool
This Python script performs various checks on IP addresses, including identifying whether they are public or private, checking if they are VPN/Proxy IPs, and fetching IP address details from an external API.It also helps in giving the traceroute results for the given IP Address.

# Features
**IP Type Check** : Determines whether an IP address is IPv4 or IPv6.\
**Public/Private IP Check**: Identifies if an IP address is private, public, or reserved by ISP (CGNAT).\
**VPN/Proxy Detection**: Checks if an IP address is listed in a local file of proxy/VPN IPs.\
**IPv6 Range Check**: Determines if an IPv6 address falls within a range specified in a local file.\
**IP Details Retrieval**: Fetches detailed information about an IP address using an external API.\
**Traceroute**: Gives the traceroute for the given IP Address.
**GUI**: Has an interactive user interface.

# Requirements
Before running the IP Analysis Tool, ensure you have the following dependencies installed:

```bash
pip install -r requirements.txt
