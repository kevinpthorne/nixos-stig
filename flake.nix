{
  description = "STIG-compliant NixOS configuration as a flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self }: {
    nixosModules = {
      nixos-stig = import ./default.nix;
    };
  };
}
