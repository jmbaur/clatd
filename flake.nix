{
  description = "clatd";
  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }: {
    overlays.default = _: prev: {
      clatd = prev.callPackage ./package.nix { };
    };
    nixosModules.default = {
      nixpkgs.overlays = [ self.overlays.default ];
      imports = [ ./module.nix ];
    };
    legacyPackages = nixpkgs.lib.genAttrs
      [ "aarch64-linux" "x86_64-linux" ]
      (system: import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      });
    devShells = nixpkgs.lib.mapAttrs
      (_: pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ pkgs.clatd ];
        };
      })
      self.legacyPackages;
  };
}
