# Changelog

## Unreleased

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
