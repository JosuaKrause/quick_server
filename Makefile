help:
	@echo "The following make targets are available:"
	@echo "lint-type-check	run type check"
	@echo "publish	publish the library on pypi"

lint-type-check:
	mypy . --config-file mypy.ini

VERSION=`echo "import quick_server;print(quick_server.__version__)" | python3 2>/dev/null`

publish:
	@git diff --exit-code 2>&1 >/dev/null && git diff --cached --exit-code 2>&1 >/dev/null || (echo "working copy is not clean" && exit 1)
	@test -z `git ls-files --other --exclude-standard --directory` || (echo "there are untracked files" && exit 1)
	@test `git rev-parse --abbrev-ref HEAD` = "master" || (echo "not on master" && exit 1)
	python3 setup.py sdist bdist_wheel
	twine upload dist/quick_server-$(VERSION)-py2.py3-none-any.whl dist/quick_server-$(VERSION).tar.gz
	git tag "v$(VERSION)"
	git push origin "v$(VERSION)"
	@echo "succesfully deployed $(VERSION)"
