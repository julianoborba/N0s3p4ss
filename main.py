from argparse import ArgumentParser
from n0s3p4ss.sniffer import sniff
from json import dumps
from n0s3p4ss.custom_json_logger import output_logger

IS_ENABLED = 1

if __name__ == '__main__':
    argument_parser = ArgumentParser(
        usage='pipenv run python3 main.py --domains [target_domains]'
    )

    required_arguments = argument_parser.add_argument_group(
        'required arguments'
    )
    required_arguments.add_argument(
        '--domains',
        metavar='target_domains',
        type=str,
        required=True,
        help='Domains to be analysed',
        nargs='+'
    )

    target_domains = argument_parser.parse_args().domains

    output_logger.info(
        dumps(sniff(target_domains), indent=IS_ENABLED)
    )
