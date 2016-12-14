#   Makefile
#
#

.PHONY: example

PYTHON3 := $(shell which python3)
PIP3    := $(shell which pip3)

example:
	$(PIP3) install --upgrade requests-mv-integrations
	$(PYTHON3) example_country_convert.py