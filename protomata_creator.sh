#!/bin/bash

if [[ $# -ne 3 ]]; then
	echo "Usage $0 <input file> <output folder> < number to grab >"
	exit 1
fi

rm -rf $2
mkdir -p $2

counter=0
for line in $(cat $1); do
	echo $line > $2/$counter.regex
	counter=$((counter + 1))

	if [[ $counter -gt $3 ]]; then
		break
	fi
done

./convert_to_anml.sh $2/*.regex
