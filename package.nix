{ lib, rustPlatform }:
let
  package = (lib.importTOML ./Cargo.toml).package;
in
rustPlatform.buildRustPackage {
  pname = package.name;
  version = package.version;
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./build.rs ./wrapper.h ./src ];
  };
  cargoLock.lockFile = ./Cargo.lock;
  nativeBuildInputs = [ rustPlatform.bindgenHook ];
  meta.mainProgram = "clatd";
}
