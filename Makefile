clean:
	pipenv clean

install:
	pipenv install

install_submodules:
	git submodule init
	git submodule update

install_sublist3r:
	pipenv install -r Sublist3r/requirements.txt
	touch ./Sublist3r/__init__.py

install_wafw00f:
	(cd ./wafw00f && sudo python3 setup.py install)

lint:
	pipenv run flake8
	autopep8 --in-place --recursive .

sonar_scanner:
	SONAR_TOKEN=${SONAR_TOKEN} PROJECT_VERSION=$(git rev-parse --short HEAD)  envsubst < sonar-project.template.properties > sonar-project.properties
	docker run -ti -v ~/project:/usr/src vivareal/sonar-scanner:latest 