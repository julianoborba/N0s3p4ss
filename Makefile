clean:
	pipenv clean

install:
	pipenv install
	git submodule init
	git submodule update
	touch ./Sublist3r/__init__.py

lint:
	pipenv run flake8 --exclude="./Sublist3r"
	pipenv run autopep8 --in-place --exclude="./Sublist3r" --recursive .

test:
	pipenv run python3 -m unittest discover tests -f

coverage:
	pipenv run coverage run --source n0s3p4ss -m unittest discover
	pipenv run coverage report --fail-under=80

.PHONY: sonar_analysis
sonar_analysis:
	sed -e 's/PROJECT_VERSION/${PROJECT_VERSION}/' < sonar-project.template.properties > sonar-project.properties
	sed -e 's/SONAR_LOGIN/${SONAR_LOGIN}/' < sonar-project.template.properties > sonar-project.properties
	docker run -ti -v $(shell pwd):/usr/src vivareal/sonar-scanner:latest
