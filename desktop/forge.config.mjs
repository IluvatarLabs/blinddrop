export default {
  packagerConfig: {
    name: "BlindDrop",
    appBundleId: "com.iluvatarlabs.blinddrop",
    asar: true,
  },
  makers: [
    {
      name: "@electron-forge/maker-zip",
      platforms: ["darwin"],
    },
  ],
};
