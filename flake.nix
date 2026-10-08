{
  description = "sshbox: minimal SSH server in a bubblewrap jail";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.buildGoModule {
            pname = "sshbox";
            version = "0.1.0";
            src = ./.;
            vendorHash = "sha256-tZelT9Xb0mlVYjVwGKM+AsvYcz+qcyM1I7O5gkV5o+g=";
            subPackages = [ "cmd" ];
            checkFlags = [ "./..." ];
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postInstall = ''
              mv $out/bin/cmd $out/bin/sshbox
              wrapProgram $out/bin/sshbox \
                --prefix PATH : ${
                  pkgs.lib.makeBinPath [
                    pkgs.bubblewrap
                    pkgs.bash
                    pkgs.coreutils
                  ]
                }
            '';
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go
              gopls
              gotools
              bubblewrap
              openssh
            ];
          };
        }
      );
    };
}
