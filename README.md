# N0s3p4ss

N0s3p4ss is an automated audition tool for Internet facing services. It gives visibility for the following informations:
```bash
- If it is possible to access target via TOR Browser
- Open Ports
- The absence of critical headers or disclosed information through headers
- SSL certificate
- Web Application Firewall detection
```

- __[Installation](#install)__
    - ____[Install Dependecies](#pipenv)____
    - ____[Clean Environment](#clean)____
- __[Usage](#usage)__
    - ____[Main Audit](#main)____
- __[Tests](#tests)__
    - ____[Code lint](#lint)____
    - ____[Code Coverage](#coverage)____
    - ____[Unittest](#unittest)____


## <a name="install"></a>Installation

<a name="pipenv"></a>**Install Dependecies**  

To install dependencies, run: 
```bash
make install
```

<a name="clean"></a>**Clean Environment**

To clean all enviroment dependencies from [pipenv](https://pipenv-fork.readthedocs.io/en/latest/), run:
```bash
make clean
```

## <a name="usage"></a>Usage

You need to have a TOR Browser Bundle instance running in order to enable N0s3p4ss TOR accessibility verification.

Also you need nmap already installed.

You may need to customize the proxy server IP address at n0s3p4ss/config.py.

N0s3p4ss audition can be executed through [pipenv](https://pipenv-fork.readthedocs.io/en/latest/), run:
```bash
pipenv run python3 main.py --domains 'target_domains'
```

For additional help, run:
```bash
pipenv run python3 main.py -h
```

## <a name="tests"></a>Tests

<a name="lint"></a>**Code Lint**  

[flake8](https://pypi.org/project/flake8/) is used to analyse the code and provide corrections and best practices, run:
```bash
make lint
```

<a name="coverage"></a>**Code Coverage**

Test coverage metrics is provided through [coverage](https://pypi.org/project/coverage/). A coverage test percentage for each file will be shown, run:
```bash
make coverage
```

<a name="unittest"></a>**Unittest**

Each test can be executed through [unittest](https://docs.python.org/3/library/unittest.html), run:
```bash
make test
```


