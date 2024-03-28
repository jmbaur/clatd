{ config, lib, pkgs, ... }: {
  options.networking.clatd.enable = lib.mkEnableOption "clatd";

  config = lib.mkIf config.networking.clatd.enable {
    systemd.services.clatd = {
      after = [ "modprobe@tun.service" "network.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = lib.getExe pkgs.clatd;
        DynamicUser = true;
        TemporaryFileSystem = [ "/" ];
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        RestrictAddressFamilies = [ "AF_NETLINK" ];
        RestrictNamespaces = [ "net" ];
        SystemCallFilter = [ "@system-service" ];
      };
    };
  };
}
