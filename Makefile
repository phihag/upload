test:
	flake8 .
	python -m unittest discover test

.PHONY: test
