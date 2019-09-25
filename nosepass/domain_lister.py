from Sublist3r.sublist3r import main
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures._base import TimeoutError
from nosepass.custom_json_logger import getLogger


class SubdomainList:

    def list_subdomains(self, domain):
        return main(
            domain,
            40,
            ports=None,
            savefile=False,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None
        )

    def list_each_domain_subdomains(self, target_domains, threads=10):
        if not target_domains:
            return []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            try:
                iterator = executor.map(self.list_subdomains, target_domains)
            except TimeoutError as timeout_error:
                getLogger().error(
                    'Error while trying to map target domains to iterator, '
                    'cause %s',
                    timeout_error,
                    exc_info=1
                )
                return []
            subdomain_listing_iteration = zip(target_domains, iterator)
            subdomains = []
            for subdomain in subdomain_listing_iteration:
                subdomains.append(subdomain)
            return subdomains
