#!/bin/bash
DOSPATH="$1"

if [ "$2" ]; then
    export WCHOST="$2"
fi

src/dosbox -c "mount c $DOSPATH" -c "c:" -c "wc"
