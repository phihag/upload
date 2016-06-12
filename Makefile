test:
	flake8 .
	python3 -m unittest discover test

.PHONY: test
