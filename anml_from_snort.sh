#!/bin/bash
set -eu

if [[ $# -ne 2 ]] || $1 == "-h" ]]; then
	echo "Usage: $0 <snort rules file> <output folder>"
	echo "Produces a number of ANML files that are the regular expressions for each distinct group"
	exit 1
fi

set -x
output=$2
rm -rf $output
python regex_group_extractor.py $1 $output
for f in $output/*; do
	if [[ $(wc -l $f | cut -f1 -d' ') -gt 0 ]]; then
		pcre2mnrl $f $f.mnrl
		vasim $f.mnrl -a
		mv automata_0.anml $f.anml
		rm $f.mnrl
	fi
	rm $f
done
