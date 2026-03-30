# STFixer (aka CloudFix)

Originally just a fix for the 'broken Capcom game saves' problem that is caused by SteamTools jank. Now it does that, but also a lot of other things too!

> Please disable Steam Cloud for non-owned games in their Steam properties. Manually backup your saves for all non-owned games!

## What?

SteamTools messes with Steam Cloud requests to "fix" Steam Cloud for non-owned games so that save syncing functions. It has those games read/write the App ID for Steam Screenshots! This causes all kinds of problems! Capcom titles are super impacted - the majority of Capcom titles released in the last few years will simply refuse to save at all in this scenario.

This tool fixes this behavior by disabling the SteamTools cloud "fix" and instead allowing Steam Cloud saving to fail to sync, as they should.

It also fixes other weird SteamTools behaviors. You can install SteamTools, even if their backend is down. You can replace the SteamTools manifest endpoint with a different one. It can diagnose a broken SteamTools install and repair it. It's a good tool.


## Usage

1. Download `CloudFix.exe` from the [latest release](https://github.com/Selectively11/CloudFix/releases/latest)
2. Run it
3. Select whichever patch you want
4. Restart Steam when prompted, or return to the main menu and run any other patches you want. Once you are done, restart Steam.

To undo the patch, run CloudFix again and select **Disable (restore originals)**.

If you get a Capcom save error even after enabling this tool, disable Steam Cloud for the affected game in the Steam properties page for that game, clear the userdata folder for the game (`<Steam install path>\userdata\<steamid>\<appid>`), restart Steam, and try again.

## What we do

CloudFix patches the SteamTools DLLs as well as its encrypted payload cache to make it better. Original files are backed up automatically and can be restored at any time through the Disable option.

## Notes

- CloudFix auto-detects your Steam install path from the registry, but you can override this
- Backups are created before any changes are made
- If SteamTools updates, you may need to re-run CloudFix
- The tool checks for updates on launch
- This tool is likely to break with an update to SteamTools, but I use SteamTools personally so you can expect me to keep it up to date.
