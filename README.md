# DiamaneOS eSIM

DiamaneOS's eSIM manager (LPA) for phones with an embedded SIM (eUICC). It
manages the profiles already on the eUICC. It does not download new ones.

## What it does

- Implements Android's `EuiccService`, so Settings and the telephony framework
  can list, turn on and off, rename and delete eSIM profiles.
- An "eSIM" screen in the Settings style: the EID (hidden until tapped) and the
  profiles, each with turn on or off, rename and delete, all confirmed.
- No launcher icon: Settings opens the screen (Network & internet > Manage
  eSIMs).
- Test profiles stay hidden unless one is turned on.
- Warns before a change turns off a profile that its carrier set to be deleted
  when turned off.
  - Turning on another profile asks again if the one that is on changed while
    the dialog was open.
- Erases the eUICC's operational profiles when Android asks for it.
- Card commands are Android's own (`EuiccCardManager`, served by
  `EuiccCardController` in the phone process over the radio's logical
  channels).

## Off by default

- The package ships disabled. Settings > Network & internet > eSIM support turns
  it on and restarts the phone, as GrapheneOS does for Google's eSIM app.
- The DiamaneOS Settings fork points that switch at this package.
- While it is off, Android binds no LPA and installed eSIMs keep working as SIMs.

## Privacy and security

- No network access (no `INTERNET` permission). No analytics. No backup.
- Never logs the EID, an ICCID or an IMSI: logs carry steps, result codes and
  counts. `dumpsys econtroller` prints counts only.
- The framework's eUICC transport logs every command and answer in full at
  verbose level, so the device keeps its tags (`TransApdu`, `ApduSender-*`)
  at info.
- Two privileged permissions, with an exact allowlist
  (`privapp-permissions-de.diamaneos.euicc.xml`):
  - `WRITE_EMBEDDED_SUBSCRIPTIONS`: Android binds only an LPA that holds it.
    The screen also uses it to ask Android to re-read the profiles.
  - `READ_PRIVILEGED_PHONE_STATE`: the SIM slot list, which gives the eUICC's
    card ID that every card command needs.
- Only the phone process can bind the service (`BIND_EUICC_SERVICE`) or open
  the Settings entry points, and the phone process takes card commands only
  from the active LPA package.
- Signed with the default app key, not the platform key. It runs in the
  platform's `priv_app` SELinux domain, with no policy of its own.
- The screen is for the system user only, honours the "no changes to mobile
  networks" restriction and ignores taps while another app covers it.

## Limits

- No downloads: no activation codes, no carrier servers.
- Turning off or deleting a profile sends no notification to the carrier. The
  eUICC keeps those SGP.22 notifications queued.
- One enabled profile at a time (no multiple enabled profiles).
- Profiles survive a factory reset unless Android recorded a download or
  developer options are on.

## Build

- `DiamaneOSEuicc`: the app (system_ext, privileged) and its allowlist.
- `DiamaneOSEuiccTests`: host unit tests for the profile list, the switch and
  delete plans, result codes, nicknames and EUICCInfo2
  (`atest DiamaneOSEuiccTests`).
- A device adds `DiamaneOSEuicc` to `PRODUCT_PACKAGES` and lists its built-in
  eUICC slots in the framework overlay (`non_removable_euicc_slots`).

## Licence

Apache-2.0 ([LICENSE](LICENSE)). Written from the GSMA specifications
(SGP.22 v2.5, SGP.26) and Android's API, with no code from other LPAs.
