from unittest import TestCase
from subprocess import STDOUT, Popen, PIPE
from os.path import abspath, dirname
from os import environ

TESTS_PATH = abspath(dirname(__file__))


class MainTest(TestCase):

    def setUp(self):
        environ['PIPENV_VERBOSITY'] = '-1'

    def test_that_should_print_help_description(self):
        process = Popen(['pipenv',
                         'run',
                         'python3',
                         f'{TESTS_PATH}/../main.py', '-h'],
                        stdout=PIPE,
                        stderr=STDOUT)

        stdout, stderr = process.communicate()

        self.assertTrue('show this help message and exit' in str(stdout))
        self.assertIsNone(stderr)

    def test_that_should_alert_domain_param_as_required(self):
        process = Popen(['pipenv',
                         'run',
                         'python3',
                         f'{TESTS_PATH}/../main.py'],
                        stdout=PIPE,
                        stderr=STDOUT)

        stdout, stderr = process.communicate()

        self.assertTrue(
            'the following arguments are required' in str(stdout)
        )
        self.assertIsNone(stderr)
