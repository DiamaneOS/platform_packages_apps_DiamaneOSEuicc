# DiamaneOS eSIM

DiamaneOS's eSIM manager (LPA) for phones with an embedded SIM (eUICC). It
manages the profiles on the eUICC and downloads new ones (GSMA SGP.22 v2,
consumer devices).

## What it does

- Implements Android's `EuiccService`, so Settings and the telephony framework
  can list, turn on and off, rename, delete and download eSIM profiles.
- An "eSIM" screen in the Settings style: "Add eSIM", the EID (hidden until
  tapped), the profiles with turn on or off, rename and delete, all confirmed,
  and the carrier notifications the eUICC still holds.
- "Add eSIM" (also Settings' "Add SIM"): scan, paste or type an activation
  code, search the eUICC's discovery server, or check a code without using it.
- Erases the eUICC's operational profiles when Android asks for it.
- Card commands are Android's own (`EuiccCardManager`, served by
  `EuiccCardController` in the phone process over the radio's logical
  channels). The framework builds the ES10 commands and segments the Bound
  Profile Package; this app runs the ES9+/ES11 side and checks the data.

## Off by default

- The package ships disabled. Settings > Network & internet > eSIM support turns
  it on and restarts the phone, as GrapheneOS does for Google's eSIM app; the
  DiamaneOS Settings fork points that switch at this package.
- While it is off, Android binds no LPA and installed eSIMs keep working as SIMs.

## Downloads (SGP.22 v2.5, 3.1.2 and 3.1.3)

- Nothing is sent before the user agrees on a dialog that names the server and
  what it receives: the EID, the IMEI, the model code (TAC) and the radio
  capabilities (Android's device information, 4.2).
- Activation codes (4.1): `LPA:1$<SM-DP+>$<matching ID>[$<OID>[$1]]`, or the
  SM-DP+ address and activation code typed separately. The OID, if given, must
  be in the server's certificate.
- Checks before the eUICC signs anything: the server signed this session's
  challenge and the address the code names; it uses a CI the eUICC signs with.
- The profile's provider, name, class, policy rules and notification events
  are shown before the download, with the confirmation code prompt when the
  code or the server asks for one (hashed as 3.1.3 requires).
- Never turns the new profile on; that is a separate choice in the list.
- "Not now", Stop and errors before the package download cancel the session on
  the eUICC and the server as "postponed" ("timeout" without an answer): the
  only reasons that keep the operator's order usable (5.7.14).
- The download goes through `EuiccManager.downloadSubscription`, so Android
  records it (subscription refresh, and a later factory reset erases eSIMs).
  The service runs only the download the user started on this screen; other
  apps' requests, metadata lookups and the default download list are refused.
- Check a code without using it: TLS, InitiateAuthentication and the eUICC's
  AuthenticateServer with an empty matching ID, then the eUICC session is
  cancelled. The server never sees the matching ID.
- Search (3.6.2, ES11): only when tapped, at the root SM-DS the eUICC names.

## Network and TLS (6.1 to 6.5, 4.5.2)

- HTTPS POST to the SM-DP+ or SM-DS host from the code, the search or a
  notification only: port 443, no redirects, timeouts on connect and every
  read, a fresh TLS context per session, no cookies, cache or compression.
- Trust anchors: only the GSMA production CI roots in `res/raw` whose key
  identifier the eUICC lists for verification (EUICCInfo1). Never system or
  user CAs, never a test CI (SGP.26 publishes their keys).
  `network_security_config.xml` trusts nothing for anything else.
- The server certificate: RFC 5280 path to such a root, valid now, extended
  key usage serverAuth, the TLS role in its policies if it has any
  (`id-rspRole-dp-tls` or `-ds-tls`), a dNSName for the host. No revocation
  check (optional for the LPA in 4.5.2.2).
- Responses: 64 KB, or 2 MB for the Bound Profile Package; strict JSON (UTF-8,
  no duplicates, limits on depth, sizes and counts), strict base64, and DER
  that must be the expected object.

## GSMA CI roots

| File | Subject | Key ID | SHA-256 (DER) |
| --- | --- | --- | --- |
| `gsma_ci_rsp2_root_ci1.pem` | GSM Association - RSP2 Root CI1 (DigiCert), valid to 2052 | `81370f51…` | `5e3e91fd…a56bb3` |
| `gsma_ci_oiste_g1.pem` | OISTE GSMA CI G1 (WISeKey), valid to 2059 | `4c27967a…` | `9c9fa2e9…d7a1a2` |

- These are the two production CIs GSMA lists for SGP.21/SGP.22 on its
  "eSIM Certificates" page (gsma.com/solutions-and-impact/technologies/esim/gsma-root-ci).
- Copies taken from the osmocom eUICC manual's CI list
  (euicc-manual.osmocom.org/docs/pki/ci) on 2026-10-06 and verified there and
  then: self-signed, key IDs as listed by GSMA, and each CI's own CRL (from
  gsma-crl.symauth.com and public.wisekey.com) verifies with the certificate's
  key. Live SM-DP+ and the GSMA root SM-DS chain to CI1.
- The app uses a root only if it is a known production CI, self-signed, a CA
  and valid (`GsmaCi.checkRoot`); `TlsPolicyTest` checks the shipped files.

## Notifications (3.5)

- Sent only for profiles downloaded here, only to the address in each
  notification, grouped by server and in sequence order, right after the
  user's own change (install, turn on or off, delete). Acknowledged ones are
  removed from the eUICC.
- Every other notification stays queued; the screen lists them (event and
  server) to send (profiles from here) or remove.
- "Downloaded here" is a salted SHA-256 hash of each ICCID in the app's
  credential-encrypted storage; nothing else is stored.

## QR codes

- No camera permission. "Scan QR code" opens the camera app; its QR mode
  reads the code and copies it, and the app pastes it on return.
- Least privilege: no image decoding in this privileged, networked process
  and no photo files. The clipboard copy is cleared after a download.

## Privacy and security

- No analytics. No network except as above. No backup. The Add eSIM window is
  secure (no screenshots or recents preview of codes).
- Never logs the EID, an ICCID, an IMSI, a code or a server: logs carry steps,
  result codes, counts and public CI names; `dumpsys econtroller` prints
  versions, capabilities, CI names and counts.
- The framework's eUICC transport logs every command and answer in full at
  verbose level; the device keeps its tags (`TransApdu`, `ApduSender-*`) at
  info.
- Three permissions, two privileged with an exact allowlist
  (`privapp-permissions-de.diamaneos.euicc.xml`):
  - `WRITE_EMBEDDED_SUBSCRIPTIONS`: Android binds only an LPA that holds it;
    the screens also use it to start downloads and refreshes.
  - `READ_PRIVILEGED_PHONE_STATE`: the SIM slot list, which gives the eUICC's
    card ID that every card command needs.
  - `INTERNET`: the downloads, checks, searches and notifications above.
- Only the phone process can bind the service (`BIND_EUICC_SERVICE`) or open
  the Settings entry points, and the phone process takes card commands only
  from the active LPA package.
- Signed with the default app key, not the platform key; runs in the platform's
  `priv_app` SELinux domain, with no policy of its own.
- The screens are for the system user only, honour the "no changes to mobile
  networks" restriction and ignore taps while another app covers them.

## Limits

- One enabled profile at a time (no multiple enabled profiles).
- Android's card command always adds the IMEI to the device information the
  eUICC signs for the server.
- The default SM-DP+ address (ES10a) is not used; the TLS trusted_ca_keys
  extension is not sent.
- Profiles survive a factory reset unless Android recorded a download or
  developer options are on.

## Build

- `DiamaneOSEuicc`: the app (system_ext, privileged) and its allowlist.
- `DiamaneOSEuiccTests`: host unit tests (`atest DiamaneOSEuiccTests`) for the
  profile list, plans, result codes, nicknames, the activation code, BER and
  DER, the SGP.22 objects, strict JSON, the ES9+ messages, TLS pinning with
  synthetic and recorded certificates, and the download and notification
  flows with a scripted eUICC and server.
- A device adds `DiamaneOSEuicc` to `PRODUCT_PACKAGES` and lists its built-in
  eUICC slots in the framework overlay (`non_removable_euicc_slots`).

## Licence

Apache-2.0; see [LICENSE](LICENSE). Written from the GSMA specifications
(SGP.22 v2.5, SGP.26) and Android's API; no code from other LPAs.
