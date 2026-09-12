# CyberFronSecurity Windows build

## Prerequisites

- Windows 10 or 11
- Node.js 20 LTS or newer
- npm 10 or newer
- A code-signing certificate for production distribution (recommended)

## Build and run

From the project root:

```powershell
npm install
npm start
```

Create an unpacked Windows build for a smoke test:

```powershell
npm run dist:dir
```

Create the distributable installer:

```powershell
npm run dist
```

The installer is written to:

```text
dist/CyberFronSecurity-Setup.exe
```

The NSIS configuration creates a Start Menu entry and a desktop shortcut. Before public release, sign the installer and application binaries with the organization certificate, publish the signed artifact over HTTPS, and update the website's `installerUrl` in `index.js` to the release URL. Do not publish an unsigned installer as an official security product.

## Release versioning

Update the `version` field in `package.json` before each release. The Electron app reads that value at runtime and displays it in the desktop UI. The website fallback is kept in sync in `index.js` until the hosted site can provide a release manifest.
