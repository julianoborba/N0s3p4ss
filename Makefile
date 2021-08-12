clean:
	pipenv clean

install:
	pipenv install
	git submodule init
	git submodule update --remote
	touch ./Sublist3r/__init__.py

lint:
	pipenv run flake8 --exclude="./Sublist3r"
	pipenv run autopep8 --in-place --exclude="./Sublist3r" --recursive .

test:
	pipenv run python3 -m unittest discover tests -f

coverage:
	pipenv run coverage run --source n0s3p4ss -m unittest discover
	pipenv run coverage report --fail-under=80

