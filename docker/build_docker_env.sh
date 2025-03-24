#!/bin/bash

# prerequisite: install docker
docker build . -f env.Dockerfile -t hmvba-test-env
