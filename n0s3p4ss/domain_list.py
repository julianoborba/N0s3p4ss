from Sublist3r.sublist3r import main
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from n0s3p4ss.custom_json_logger import custom_logger
from itertools import chain

IS_ENABLED = True


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
                custom_logger.error(
                    f'Error while trying to enumerate subdomains '
                    f'from domains, cause {timeout_error}',
                    exc_info=IS_ENABLED
                )
                return []
            return [subdomains for subdomains in subdomains_listing_iteration]
