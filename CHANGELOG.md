# Changelog

## Unreleased

- Scanning without copy and paste: "Scan QR code" opens the camera app's
  QR scanner directly, and its "Open with" hands an `LPA:` code to Add eSIM
  (any app on the phone can; web pages can't). The user still agrees before
  anything connects. The Add eSIM windows now hide other apps' overlays.
  Not yet built.
- No launcher icon, as on GrapheneOS: Settings opens the eSIM screen (Network
  & internet > Manage eSIMs, while eSIM support is on) through the standard
  manage-eSIMs action, which only the phone process can forward. The screen
  itself is no longer exported. Not yet built.
- Deleting an enabled eSIM whose carrier set it to be deleted when turned
  off reports success: the eUICC had already removed it, but the screen
  said "Couldn't finish" and the framework's list was not refreshed.
  Not yet built.
- Turning on another eSIM warns when the carrier set the one being turned
  off to be deleted when it is turned off, as turning it off already does.
  Not yet built.
- Download eSIMs (GSMA SGP.22 v2 consumer download). Not yet built.
  - "Add eSIM" on the eSIM screen and Settings' "Add SIM": scan (camera app's
    QR mode, then paste), paste or type an activation code; confirmation code
    when required; never turns the new profile on.
  - The user agrees before any connection, on a dialog that names the server
    and what it receives. "Not now" and Stop before the package download keep
    the code usable.
  - "Check a code without using it": the server's TLS and the eUICC's checks,
    without sending the matching ID. "Search for available eSIMs" (SM-DS),
    only when tapped.
  - HTTPS to the code's server only, trusting only the shipped GSMA CI roots
    that the eUICC also lists; strict, size-limited parsing.
  - Notifications only for profiles downloaded here, to the server in each,
    after the user's change; the rest stay listed to send or remove.
  - New permission: `INTERNET`. Stores salted hashes of the ICCIDs it
    installed. Logs no identifiers, codes or servers.
- `dumpsys econtroller` adds the eUICC's SGP.22 versions, capabilities, CI
  names and notification counts.

## 2026-10-06

- First version: list, turn on and off, rename, delete and erase the profiles
  on the eUICC, behind GrapheneOS's eSIM support switch. Checked on a Fairphone
  6: the ISD-R channel, the profile list, and turning a profile off and on.
