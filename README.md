# Nosepass

<img src="https://pokemonqrcode.com/image/cache/catalog/Pokemon/Gen3/nosepass-500x500.jpg" width="250" height="250"/>

Nosepass is an automated audition tool for Internet facing services. It gives visibility for the following informations:
```bash
- If it is possible to access target via tor browser
- Open Ports
- The absence of critical headers or disclosed information through headers
- SSL certificate
- Web Application Firewall detection
```

- __[Installation](#install)__
    - ____[Install Dependecies](#pipenv)____
    - ____[Clean Environment](#clean)____
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

To clean all enviroment dependencies from [pipenv](https://pipenv-fork.readthedocs.io/en/latest/) ,run:
```bash
make clean
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


