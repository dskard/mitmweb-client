PYTESTOPTS?=

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
