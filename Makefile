PROJECT=mitmweb-client
PYTESTOPTS?=
PYTHON_VERSION?=3.9.11

.PHONY: pyenv
pyenv:
	pyenv install ${PYTHON_VERSION} --skip-existing
	pyenv uninstall ${PROJECT} || true
	pyenv virtualenv ${PYTHON_VERSION} ${PROJECT}
	pyenv local ${PROJECT}
	pip install black pytest pdbpp poetry
	sed -i '/export VIRTUAL_ENV=/d' .envrc || true
	echo "export VIRTUAL_ENV=\$$$\(pyenv prefix)" >> .envrc
	direnv allow || true

.PHONY: all
all:
	poetry build

.PHONY: install
install:
	poetry install

.PHONY: test
test:
	poetry run pytest \
	    --verbose \
	    --tb=short \
	    ${PYTESTOPTS}

.PHONY: clean
clean:
	find . \( -name '*.pyc' -or -name '*.pyo' \) -print -delete
	find . -name '__pycache__' -print -delete
