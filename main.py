from argparse import ArgumentParser

argument_parser = ArgumentParser(
    usage='pipenv run python3 main.py --url [target_url]'
)

required_arguments = argument_parser.add_argument_group('required arguments')
required_arguments.add_argument(
    '--url',
    metavar='target_url',
    type=str,
    required=True,
    help='A url string target that going to be analysed'
)

argument_parser.parse_args()
