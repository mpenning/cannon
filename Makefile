.PHONY: pypi
pypi:
	make clean
	python setup.py register -r pypi
	python setup.py bdist_wheel sdist
	twine upload dist/*
.PHONY: repo-push
repo-push:
	git push git@github.com:mpenning/cannon.git
.PHONY: test
test:
	# Run the doc tests and unit tests
	cd tests; ./runtests.sh
.PHONY: clean
clean:
	find ./* -name '*.pyc' -exec rm {} \;
	find ./* -name '*.so' -exec rm {} \;
	find ./* -name '*.coverage' -exec rm {} \;
	@# A minus sign prefixing the line means it ignores the return value
	-find ./* -path '*__pycache__' -exec rm -rf {} \;
	-rm -rf .pytest_cache/
	-rm -rf .eggs/
	-rm -rf .cache/
	-rm -rf build/ dist/ cannon.egg-info/ setuptools*
