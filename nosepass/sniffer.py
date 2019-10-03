from nosepass.domain_list import SubdomainList
from nosepass.attack_surface_discoverer import discover


def sniff(target_domains):
    subdomains = SubdomainList().list_each_domain_subdomains(target_domains)
    return [discover(subdomain) for subdomain in subdomains]
