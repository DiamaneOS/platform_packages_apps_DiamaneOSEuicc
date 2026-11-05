# Host build and fuzz targets

A Gradle build of `src/de/diamaneos/euicc/core` and the host tests in `tests/src`, as
`DiamaneOSEuiccTests` builds them, plus Jazzer fuzz targets for the parsers of server, code and
card data. Not part of the platform build.

- `gradle test`: the host tests.
- `./fuzz.sh run <Target> <seconds> [dir]`: fuzz one target from its seeds (coverage guided).
- `./fuzz.sh replay <Target> <files or dirs>`: run inputs once, for example a corpus or a finding.
- Seeds are built by `Seeds` with the tests' encoder. Seeds, corpora and findings stay under
  `build/` and are not committed.
- Dependencies, for this build only: Kotlin 2.0.21, JUnit 4.13.2, Jazzer 0.30.0. Versions are in
  `gradle.lockfile`, checksums in `gradle/verification-metadata.xml`.

## Targets

| Target | Input | Checks |
| --- | --- | --- |
| `BerFuzz` | any BER-TLV | only IllegalArgumentException, DER round trip, no tag in a forbidden form, primitive readers |
| `JsonFuzz` | an ES9+ body | only JsonException, limits, round trip |
| `Es9Fuzz` | an ES9+ or ES11 body | only the expected failures, one TLV per binary member |
| `ServerSignedFuzz` | ServerSigned1, SmdpSigned2 | one reading: no repeated component, no aliased tag |
| `MetadataFuzz` | StoreMetadataRequest | one reading under every reader model, clean labels |
| `BppFuzz` | consent metadata and a Bound Profile Package | what the eUICC receives matches the consent under every reader model |
| `DownloadFlowFuzz` | the server's bodies and the eUICC's answers | order, consent before install, installed metadata, signed address, hosts contacted |
| `CardResponseFuzz` | notifications and ES10 responses | only IllegalArgumentException, no throw from the tolerant readers |
| `CertificateFuzz` | a DER certificate | only GeneralSecurityException, an accepted leaf chains and names the host |
| `ActivationCodeFuzz` | codes, addresses, tokens, typed text | only Invalid, the host is the code's own field, round trip |
| `FqdnFuzz` | host names and dNSName patterns | agrees with a reference matcher |
| `ServerTextFuzz` | any UTF-16 | no hidden, reordering or line-breaking character survives |

The reader models (`MetadataModels`) read a structure the way another decoder could: the first
or the last of a repeated tag, a tag number in a forbidden form, the unused bits of a BIT STRING
counted or not, one byte of a long class. A structure the app accepts must read the same in all.
