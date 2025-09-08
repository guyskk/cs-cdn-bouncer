#!/bin/bash

set -e

# shellcheck disable=SC2068
ezfaas build \
    --repository cs-cdn-bouncer \
    --build-progress plain
