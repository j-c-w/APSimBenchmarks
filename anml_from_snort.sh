#!/bin/zsh
set -eu

typeset -a leave_regex
typeset -a leave_dups
zparseopts -D -E -leave-regex=leave_regex -leave-dups=leave_dups

if [[ $# -lt 2 ]] || [[ $1 == "-h" ]]; then
	echo "Usage: $0 <snort rules file> <output folder> [flags for python]"
	echo "Produces a number of ANML files that are the regular expressions for each distinct group"
	echo "--leave-regex: leave the regex files"
	echo "--leave-dups: leave duplicates"
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
		if [[ ${#leave_dups} == 0 ]]; then
			cat $f | sort | uniq > $f.tmp
			mv $f.tmp $f
		fi
		pcre2mnrl $f $f.mnrl
		vasim $f.mnrl -a || echo "No valid regexes"
		if [[ -f automata_0.anml ]]; then
			mv automata_0.anml $f.anml
		fi
		rm $f.mnrl
	fi
	if [[ ${#leave_regex} -eq 0 ]]; then
		rm $f
	fi
done
