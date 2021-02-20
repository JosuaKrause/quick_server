#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    import coverage  # pylint: disable=import-error
    coverage.process_startup()
# pylint: disable=bare-except
except:  # nopep8
    pass
