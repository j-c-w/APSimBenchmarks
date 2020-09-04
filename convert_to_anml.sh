#!/bin/bash
set -eu

if [[ $# -lt 1 ]]; then
	echo "Usage: $0 <files to convert>"
	exit 1
fi

while [[ $# -ne 0 ]]; do
	f=$1
	shift

	if [[ $f == *.anml ]] || [[ $f == *.mnrl ]]; then
		continue
	fi

	pcre2mnrl $f $f.mnrl
	vasim $f.mnrl -a
	if [[ -f automata_0.anml ]]; then
		mv automata_0.anml $f.anml
	fi
	rm $f.mnrl
done
