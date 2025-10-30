#!/bin/bash

# Run a single unit test module in complete isolation

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <module_name>"
    echo "Example: $0 trust_conn_fsm_unit_tests_fixed"
    exit 1
fi

MODULE_NAME="$1"

echo "=== Running $MODULE_NAME in complete isolation ==="

# Clean and compile
rebar3 clean
rebar3 as test compile

# Run only the specified module
rebar3 as test eunit --dir=test/unit --module="$MODULE_NAME"

echo "=== $MODULE_NAME completed ==="
