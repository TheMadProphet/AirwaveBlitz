#!/bin/bash

mypy . || FAIL=true

if [[ $FAIL ]]; then
    echo "Y" | mypy --install-types
    mypy .
fi
