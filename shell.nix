{ pkgs ? import<nixpkgs> {} }:

with pkgs;
mkShell {
	buildInputs = let
		pypkgs = pypkgs: with pypkgs; [
			(callPackage ~/.scripts/Nix/CustomPackages/AutomataTools/idstools/idstools.nix {})
		];
		python-wpkgs = python38.withPackages pypkgs;
		hscompile = (import ~/.scripts/Nix/CustomPackages/AutomataTools/hscompile/default.nix );
	in
	[
		python-wpkgs
		hscompile
		(callPackage ~/.scripts/Nix/CustomPackages/AutomataTools/vasim/default.nix  {})
	];
	SHELL_NAME = "Benchmarks";
	shellHook = ''
	export PYTHONPATH=$PYTHONPATH:$PWD
		'';
}
