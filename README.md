# IP_Tool
This Python script performs various checks on IP addresses, including identifying whether they are public or private, checking if they are VPN/Proxy IPs, and fetching IP address details from an external API.

# Features
**IP Type Check** : Determines whether an IP address is IPv4 or IPv6.\
**Public/Private IP Check**: Identifies if an IP address is private, public, or reserved by ISP (CGNAT).\
**VPN/Proxy Detection**: Checks if an IP address is listed in a local file of proxy/VPN IPs.\
**IPv6 Range Check**: Determines if an IPv6 address falls within a range specified in a local file.\
**IP Details Retrieval**: Fetches detailed information about an IP address using an external API.\

# Requirements
1. Python 3.x
2. requests library (for making HTTP requests)
