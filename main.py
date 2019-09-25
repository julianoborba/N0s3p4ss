from argparse import ArgumentParser
from nosepass.domain_lister import SubdomainList

argument_parser = ArgumentParser(
    usage='pipenv run python3 main.py --domains [target_domains]'
)

required_arguments = argument_parser.add_argument_group('required arguments')
required_arguments.add_argument(
    '--domains',
    metavar='target_domains',
    type=str,
    required=True,
    help='Domains to be analysed',
    nargs='+'
)

target_domains = argument_parser.parse_args().domains
subdomains = SubdomainList().list_each_domain_subdomains(target_domains)

print(subdomains)
