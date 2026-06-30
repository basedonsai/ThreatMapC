# ThreatMap Local IIS Redeploy Instructions

## Important Configuration Update (Required Once)
Because we recently changed the `UploadsPath` to fix IIS permission issues, you **must** ensure your deployed `appsettings.json` is updated.
* **Action Required:** Open `C:\inetpub\ThreatMap\appsettings.json` and ensure it has:
  `"UploadsPath": "wwwroot/uploads"`
* If you skip this, the automated script will keep backing up and restoring your *old* broken configuration!


## Option 1: Automated Redeploy (Recommended)
You do **NOT** need to manually copy files, delete files, or run `iisreset`. The script handles everything safely
**Steps:**
1. Open PowerShell in your project root folder.
2. Run:
   ```powershell
   .\redeploy.ps1
   ```
3. That's it! The script will automatically:
   * Backup your environment files (`appsettings.json`, `appsettings.Production.json`).
   * Put IIS to sleep seamlessly using `app_offline.htm` (no `iisreset` required).
   * Publish directly into `C:\inetpub\ThreatMap`.
   * Keep your `wwwroot/uploads` folder intact.
   * Restore your environment files and wake IIS back up.

## Option 2: Manual Redeploy
If you prefer not to use the script, you must do everything by hand.
**Steps:**
1. **Stop IIS:**
   ```powershell
   iisreset /stop
   ```
2. **Build and Publish Locally:**
   ```powershell
   dotnet publish -c Release -o .\publish
   ```
3. **Backup Critical Files:**
   Before copying, ensure you don't overwrite your persistent data or database credentials. Backup these files from `C:\inetpub\ThreatMap`:
   * `appsettings.json`
   * `appsettings.Production.json`
4. **Copy Files:**
   Copy everything from your `.\publish` folder into `C:\inetpub\ThreatMap`. Overwrite existing files.
5. **Restore Critical Files:**
   Copy your backed-up `appsettings.json` files back into `C:\inetpub\ThreatMap`.
6. **Start IIS:**
   ```powershell
   iisreset /start
   ```
## Validate
After redeploying (either method), open:
```text
https://localhost:5055/
```
Check:
* viewer opens
* login works
* create plot works
* upload layout works
* save works
* publish works

## Debug if broken
Check:
* Event Viewer → Application Logs
* IIS logs
* browser console
* appsettings syntax (missing commas are common)