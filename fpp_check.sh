#!/bin/bash
# Validate the FPP models against the F' framework definitions.
# Usage: FPRIME_ROOT=/path/to/fprime ./fpp_check.sh fpp/*.fpp
# Defaults to ../fprime (F' cloned next to this repository).
FPRIME_ROOT="${FPRIME_ROOT:-$(dirname "$0")/../fprime}"
if [ ! -d "$FPRIME_ROOT/Fw" ]; then
    echo "F' framework not found at $FPRIME_ROOT (set FPRIME_ROOT)" >&2
    exit 1
fi
ALL_FW=$(find "$FPRIME_ROOT/Fw/" \
              "$FPRIME_ROOT/Svc/Sched/" \
              "$FPRIME_ROOT/cmake/platform/unix/" \
              "$FPRIME_ROOT/default/config/" \
              -name "*.fpp" 2>/dev/null | tr '\n' ' ')
fpp-check $ALL_FW "$@"
