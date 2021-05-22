#!/usr/bin/env bash

black --line-length 100 --target-version py27 .
./check_code.sh
