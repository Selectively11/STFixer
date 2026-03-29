# CloudFix

A fix for the 'broken Capcom game saves' problem that is caused by SteamTools jank. Also other stuff!

> **Important: Disable Steam Cloud for affected games in their Steam properties. Manually backup your saves for all non-owned games!**

## What?

SteamTools messes with Steam Cloud requests to "fix" Steam Cloud for non-owned games so that save syncing functions. It has those games read/write the App ID for Steam Screenshots! This causes all kinds of problems! Capcom titles are super impacted - the majority of Capcom titles released in the last few years will simply refuse to save at all in this scenario.

This tool fixes this behavior by disabling the SteamTools cloud "fix" and instead allowing Steam Cloud saving to fail to sync, as it should. You can backup your saves yourself, right? Beats having to grab a fix for each game in order to save.

## Usage

1. Download `CloudFix.exe` from the [latest release](https://github.com/Selectively11/CloudFix/releases/latest)
2. Run it
3. Select **Enable** to apply the patch
4. Restart Steam when prompted

To undo the patch, run CloudFix again and select **Disable**.

If you get a Capcom save error even after enabling this tool, disable Steam Cloud for the affected game in the Steam properties page for that game, clear the userdata folder for the game (`<Steam install path>\userdata\<steamid>\<appid>`), restart Steam, and try again.

## What we do

CloudFix patches the SteamTools DLL and its encrypted payload cache to prevent it from messing with Steam Cloud. Original files are backed up automatically and can be restored at any time through the Disable option.

## Notes

- CloudFix auto-detects your Steam install path from the registry
- Backups are created before any changes are made
- If SteamTools updates, you may need to re-run CloudFix
- The tool checks for updates on launch
- This tool is likely to break with an update to SteamTools, but I use SteamTools personally so you can expect me to keep it up to date.
