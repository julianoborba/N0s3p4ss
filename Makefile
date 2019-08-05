clean:
	pipenv clean

install:
	pipenv install
	git submodule init
	git submodule update
	touch ./Sublist3r/__init__.py

lint:
	pipenv run flake8
	autopep8 --in-place --recursive .

sonar_analysis:
	SONAR_TOKEN=${SONAR_TOKEN} PROJECT_VERSION=$(git rev-parse --short HEAD)  envsubst < sonar-project.template.properties > sonar-project.properties
	docker run -ti -v ~/project:/usr/src vivareal/sonar-scanner:latest

test:
	python3 -m unittest discover tests
