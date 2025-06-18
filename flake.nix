{
  description = "STIG-compliant NixOS configuration as a flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs }: {
    nixosModules = {
      nixos-stig = import ./default.nix;
    };
  };
}
