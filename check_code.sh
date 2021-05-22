#!/usr/bin/env bash

pylint *.py
flake8 --ignore E501,W503,E402,E203,E722
