#!/bin/bash
set -eu

if [[ $# -lt 1 ]]; then
	echo "Usage: $0 <files to convert>"
	exit 1
fi

while [[ $# -ne 0 ]]; do
	f=$1
	shift

	pcre2mnrl $f $f.mnrl
	vasim $f.mnrl -a
	mv automata_0.anml $f.anml
	rm $f.mnrl
done
