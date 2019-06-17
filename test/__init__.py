try:
    import coverage
    coverage.process_startup()
# pylint: disable=bare-except
except:  # nopep8
    pass
