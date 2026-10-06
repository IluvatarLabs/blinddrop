import { fileURLToPath } from "node:url";

const signingIdentity = process.env.BLINDDROP_SIGN_IDENTITY;
const keychainProfile = process.env.BLINDDROP_NOTARY_KEYCHAIN_PROFILE;
const appleId = process.env.APPLE_ID;
const appleIdPassword = process.env.APPLE_APP_SPECIFIC_PASSWORD;
const teamId = process.env.APPLE_TEAM_ID;

const osxNotarize =
  typeof keychainProfile === "string" && keychainProfile !== ""
    ? { keychainProfile }
    : [appleId, appleIdPassword, teamId].every(value => typeof value === "string" && value !== "")
      ? { appleId, appleIdPassword, teamId }
      : null;

const packagerConfig = {
  name: "BlindDrop",
  appBundleId: "com.iluvatarlabs.blinddrop",
  icon: fileURLToPath(new URL("assets/app.icns", import.meta.url)),
  asar: true,
  // The app stages this directory into host-managed plugin locations. Keep it
  // on the real filesystem: recursive fs.cp cannot traverse a directory inside
  // app.asar. Electron Packager copies extraResource beside app.asar, where the
  // packaged app reaches it through process.resourcesPath.
  extraResource: fileURLToPath(new URL("node_modules/blinddrop/plugin", import.meta.url)),
};

// Direct-download signing needs an explicit Developer ID Application identity.
// Do not let Forge guess from unrelated Development or App Store identities.
if (typeof signingIdentity === "string" && signingIdentity !== "") {
  packagerConfig.osxSign = { identity: signingIdentity };
  if (osxNotarize !== null) packagerConfig.osxNotarize = osxNotarize;
}

export default {
  packagerConfig,
  makers: [
    {
      name: "@electron-forge/maker-zip",
      platforms: ["darwin"],
    },
  ],
};
