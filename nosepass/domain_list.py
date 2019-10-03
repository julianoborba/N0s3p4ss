from Sublist3r.sublist3r import main
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from nosepass.custom_json_logger import getLogger
from itertools import chain


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
                subdomains_listing_iteration = list(
                    chain.from_iterable(
                        executor.map(
                            self.list_subdomains,
                            target_domains
                        )
                    )
                )
            except TimeoutError as timeout_error:
                getLogger().error(
                    'Error while trying to enumerate subdomains from domains, '
                    'cause %s',
                    timeout_error,
                    exc_info=1
                )
                return []
            return [subdomains for subdomains in subdomains_listing_iteration]
