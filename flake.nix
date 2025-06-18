{
  description = "STIG-compliant NixOS configuration as a flake";

  inputs = {};

  outputs = { self }: {
    nixosModules = {
      nixos-stig = import ./default.nix;
    };
  };
}
