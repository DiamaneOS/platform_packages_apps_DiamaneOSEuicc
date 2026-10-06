# DiamaneOS eSIM

DiamaneOS's eSIM manager (LPA) for phones with an embedded SIM (eUICC). It
manages the profiles already on the eUICC; it does not download new ones.

## What it does

- Implements Android's `EuiccService`, so Settings and the telephony framework
  can list, turn on and off, rename and delete eSIM profiles.
- An "eSIM" screen in the Settings style: the EID (hidden until tapped) and the
  profiles, each with turn on or off, rename and delete, all confirmed.
- Erases the eUICC's operational profiles when Android asks for it.
- The card commands (SGP.22 ES10) are Android's own: `EuiccCardManager`, served
  by `EuiccCardController` in the phone process, which reaches the eUICC's
  management applet (ISD-R) through the radio. The app has no APDU or ASN.1
  code of its own, apart from reading the firmware version from EUICCInfo2.

## Off by default

- The package ships disabled. Settings > Network & internet > eSIM support turns
  it on and restarts the phone, as GrapheneOS does for Google's eSIM app; the
  DiamaneOS Settings fork points that switch at this package.
- While it is off, Android binds no LPA and installed eSIMs keep working as SIMs.

## Privacy and security

- No network access (no `INTERNET` permission), no analytics, no user data
  stored, no backup.
- Never logs the EID, an ICCID or an IMSI: logs carry result codes and counts,
  and `dumpsys econtroller` prints counts only.
- Two privileged permissions, with an exact allowlist
  (`privapp-permissions-de.diamaneos.euicc.xml`):
  - `WRITE_EMBEDDED_SUBSCRIPTIONS`: Android binds only an LPA that holds it;
    the screen also uses it to ask Android to re-read the profiles.
  - `READ_PRIVILEGED_PHONE_STATE`: the SIM slot list, which gives the eUICC's
    card ID that every card command needs.
- Only the phone process can bind the service (`BIND_EUICC_SERVICE`), and the
  phone process takes card commands only from the active LPA package.
- Signed with the default app key, not the platform key; runs in the platform's
  `priv_app` SELinux domain, with no policy of its own.
- The screen is for the system user only, honours the "no changes to mobile
  networks" restriction and ignores taps while another app covers it.

## Limits

- No downloads: no activation codes, no carrier servers.
- Turning off or deleting a profile sends no notification to the carrier; the
  eUICC keeps those SGP.22 notifications queued.
- One enabled profile at a time (no multiple enabled profiles).
- Profiles survive a factory reset: Android asks the LPA to erase them only on
  an installation that has downloaded a profile.

## Build

- `DiamaneOSEuicc`: the app (system_ext, privileged) and its allowlist.
- `DiamaneOSEuiccTests`: host unit tests for the profile list, the switch and
  delete plans, result codes, nicknames and EUICCInfo2
  (`atest DiamaneOSEuiccTests`).
- A device adds `DiamaneOSEuicc` to `PRODUCT_PACKAGES` and lists its built-in
  eUICC slots in the framework overlay (`non_removable_euicc_slots`).

## Licence

Apache-2.0; see [LICENSE](LICENSE).
