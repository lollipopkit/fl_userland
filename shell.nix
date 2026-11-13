{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
	nativeBuildInputs = [
		pkgs.clang
		pkgs.lld
		pkgs.sqlite
	];
}
