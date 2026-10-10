{
  description = "sshbox: minimal SSH server in a bubblewrap jail";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
          system: f nixpkgs.legacyPackages.${system}
        );
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.buildGoModule {
          pname = "sshbox";
          version = "0.1.0";
          src = ./.;
          vendorHash = "sha256-mPA9S4IyJ9NpwSLwq2AaqHLT7GznHqXxgmoJLyiznV8=";
          subPackages = [ "cmd" ];
          checkFlags = [ "./..." ];
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postInstall = ''
            mv $out/bin/cmd $out/bin/sshbox
            wrapProgram $out/bin/sshbox \
              --prefix PATH : ${
                pkgs.lib.makeBinPath (
                  with pkgs;
                  [
                    bubblewrap
                    bash
                    coreutils
                    libnatpmp
                    iptables
                    iproute2
                  ]
                )
              }
          '';
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.system}.default ];
          packages = with pkgs; [
            gopls
            gotools
            openssh
          ];
        };
      });
    };
}
