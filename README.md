This is a set of scripts for producing distinct sets of regular expression
rules.  It takes as input Snort rule format rules, and produces
as output sets of regular expressions that should be run
on distinct packets.

#Building
You need nix, and my configs to fetch the dependencies to this: get j-c-w/config,
and setup the Nix scripts.

Then just do nix-shell, and that should produce a working environment
with the appropriate dependencies
