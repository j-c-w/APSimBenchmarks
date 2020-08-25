#!/bin/zsh
set -eu

typeset -a leave_regex
zparseopts -D -E -leave-regex=leave_regex

if [[ $# -lt 2 ]] || [[ $1 == "-h" ]]; then
	echo "Usage: $0 <snort rules file> <output folder> [flags for python]"
	echo "Produces a number of ANML files that are the regular expressions for each distinct group"
	echo "--leave-regex: leave the regex files"
	echo "Python flags are:"
	python regex_group_extractor.py --help
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
	if [[ ${#leave_regex} -eq 0 ]]; then
		rm $f
	fi
done
