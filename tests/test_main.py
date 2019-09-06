from unittest import TestCase
from subprocess import run, DEVNULL, STDOUT, Popen, PIPE
from os.path import abspath, dirname
from test.support import EnvironmentVarGuard

TESTS_PATH = abspath(dirname(__file__))


class MainTest(TestCase):

    def setUp(self):
        self.environment = EnvironmentVarGuard()
        self.environment.set('PIPENV_VERBOSITY', '-1')

    def test_that_should_print_help_description(self):
        with self.environment:
            process = Popen(['pipenv',
                             'run',
                             'python3',
                             f'{TESTS_PATH}/../main.py', '-h'],
                            stdout=PIPE,
                            stderr=STDOUT)

            stdout, stderr = process.communicate()

            self.assertTrue('show this help message and exit' in str(stdout))
            self.assertIsNone(stderr)

    def test_that_should_return_success_when_using_url_param(self):
        with self.environment:
            process = str(run(
                f'pipenv run python3 {TESTS_PATH}/../main.py'
                f' --url https://www.google.com',
                stdout=DEVNULL,
                stderr=STDOUT,
                shell=True
            ))
            self.assertNotEqual(-1, process.find('returncode=0'))

    def test_that_should_alert_url_param_as_required(self):
        with self.environment:
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
