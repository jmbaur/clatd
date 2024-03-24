{ config, lib, pkgs, ... }: {
  options.networking.clatd.enable = lib.mkEnableOption "clatd";

  config = lib.mkIf config.networking.clatd.enable {
    boot.extraModulePackages = [ config.boot.kernelPackages.jool ];
    environment.systemPackages = [ pkgs.jool-cli ];
    systemd.services.clatd = {
      after = [ "modprobe@jool_siit.service" "network.target" ];
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.jool-cli ];
      serviceConfig = {
        ExecStart = lib.getExe pkgs.clatd;
        User = "jool";
        Group = "jool";
        DynamicUser = true;
        TemporaryFileSystem = [ "/" ];
        BindReadOnlyPaths = [
          builtins.storeDir
          "/run/booted-system/kernel-modules"
        ];
        AmbientCapabilities = [ "CAP_SYS_MODULE" "CAP_NET_ADMIN" ];
        RestrictAddressFamilies = [ "AF_NETLINK" ];
        RestrictNamespaces = [ "net" ];
        SystemCallFilter = [ "@system-service" "@module" ];
        CapabilityBoundingSet = [ "CAP_SYS_MODULE" "CAP_NET_ADMIN" ];
      };
    };
  };
}
