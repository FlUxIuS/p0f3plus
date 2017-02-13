#!/bin/bash 

find . -name "*.pyc" -exec rm -rf {} \;
find . | grep .git | xargs rm -rf
find . | grep __pycache__ | xargs rm -rf
