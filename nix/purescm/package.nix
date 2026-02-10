{
  lib,
  buildNpmPackage,
  fetchNpmDeps,
  testers,
}:

let
  packageLock = builtins.fromJSON (builtins.readFile ./manifests/package-lock.json);

  pname = "purescm";
  version = packageLock.packages."node_modules/${pname}".version;

  package = buildNpmPackage {
    inherit pname version;

    src = ./manifests;
    dontNpmBuild = true;

    npmDeps = fetchNpmDeps {
      src = ./manifests;
      hash = "sha256-e8BDTCp7PsriJaUivdm5IdRcdVDf9urtKnTYu1Mr2oQ=";
    };

    installPhase = ''
      mkdir -p $out/share/${pname}
      cp -r node_modules/ $out/share/${pname}
      ln -s $out/share/${pname}/node_modules/.bin $out/bin

      # Patch hardcoded ICU version suffix to match nixpkgs ICU
      sed -i 's/_74"/_76"/g' $out/share/${pname}/node_modules/${pname}/lib/${pname}/pstring.ss
    '';
    
    passthru.tests = {
      version = testers.testVersion { inherit package; };
    };

    meta = {
      description = "Chez Scheme back-end for PureScript";
      homepage = "https://github.com/purescm/purescm";
      license = lib.licenses.asl20;
      mainProgram = "purescm";
    };
  };
in
package