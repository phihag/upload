test: lint
	python3 -m unittest discover test

lint:
	flake8 .

.PHONY: lint test
