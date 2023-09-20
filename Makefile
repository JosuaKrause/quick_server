help:
	@echo "The following make targets are available:"
	@echo "install	install the library for local development (this is not meant for installing it to be used elsewhere)"
	@echo "lint-type-check	run type check"
	@echo "lint-pylint	run linter check using pylint standard"
	@echo "lint-all	run all lints"
	@echo "git-check	ensure that the working directory is clean"
	@echo "pack	build the library"
	@echo "publish	publish the library on pypi"
	@echo "run-test	run all tests"
	@echo "pre-commit 	sort python package imports using isort"

export LC_ALL=C
export LANG=C

PYTHON=python
VERSION=`echo "import quick_server;print(quick_server.__version__)" | python3 2>/dev/null`

install:
	$(PYTHON) -m pip install --progress-bar off --upgrade pip
	$(PYTHON) -m pip install --progress-bar off --upgrade mypy pylint pre-commit
	$(PYTHON) -m pip install --progress-bar off --upgrade -e .

lint-type-check:
	$(PYTHON) -m mypy src/

lint-pylint:
	sh/findpy.sh | sort
	sh/findpy.sh | sort | xargs $(PYTHON) -m pylint -j 6 -v

lint-all: \
	lint-pylint \
	lint-type-check

git-check:
	@git diff --exit-code 2>&1 >/dev/null && git diff --cached --exit-code 2>&1 >/dev/null || (echo "working copy is not clean" && exit 1)
	@test -z `git ls-files --other --exclude-standard --directory` || (echo "there are untracked files" && exit 1)
	@test `git rev-parse --abbrev-ref HEAD` = "master" || (grep -q -E "a|b|rc" <<< "$(VERSION)") || (echo "not on master" && exit 1)

pack:
	$(PYTHON) -m pip install --progress-bar off --upgrade setuptools twine wheel
	rm -r dist build src/quick_server.egg-info || echo "no files to delete"
	$(PYTHON) setup.py sdist bdist_wheel

publish: git-check pack
	$(PYTHON) -m twine upload dist/quick_server-$(VERSION)-py3-none-any.whl dist/quick_server-$(VERSION).tar.gz
	git tag "v$(VERSION)"
	git push origin "v$(VERSION)"
	@echo "succesfully deployed $(VERSION)"

run-test:
	$(PYTHON) test/run.py $(SKIP)

pre-commit:
	pre-commit install
	isort .
