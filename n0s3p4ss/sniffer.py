from n0s3p4ss.domain_list import SubdomainList
from n0s3p4ss.attack_surface_discoverer import discover
from n0s3p4ss.sniffer_switcher_http_status_based import apply_flow_for


def sniff(target_domains):
    subdomains = SubdomainList().list_each_domain_subdomains(target_domains)
    attack_surfaces = [discover(subdomain) for subdomain in subdomains]
    return [
        apply_flow_for(attack_surface) for attack_surface in attack_surfaces
    ]
