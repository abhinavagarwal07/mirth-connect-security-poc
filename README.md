# NextGen Connect 4.5.2 vulnerability PoCs

Working proof-of-concept exploits for three network-reachable vulnerabilities in
NextGen Connect (Mirth Connect) 4.5.2. The harnesses run the official container
image, create only the channel configuration needed by the finding, execute the
attack from a separate container, and fail unless the claimed security effect is
observed.

This review used the public **[Refute-or-Promote methodology](https://arxiv.org/abs/2604.19049)**
and its **[open-source orchestration playbook](https://github.com/abhinavagarwal07/refute-or-promote)**.
The method separates candidate generation from fresh-context adversarial review and
requires empirical proof before promotion. The vulnerable 4.5.2 source and the review
method are both public: anyone with ordinary model access, the source, and the ability
to validate safely in a lab can apply the same process, and could have found these bug
classes independently. Confidentiality around one report does not make the underlying
review capability private.

These are real exploits, not parser unit tests. They recover a live password hash
through SQL injection, exfiltrate target-local file contents through two distinct
unauthenticated XML paths, and block bundled-Derby-backed operations until restart.

| CVE | Finding | Attacker | Demonstrated impact | CVSS 3.1 / 4.0 | PoC |
|---|---|---|---|---|---|
| [CVE-2026-82583](https://www.cve.org/CVERecord?id=CVE-2026-82583) | `_getTables` `selectLimit` injection | Authenticated API user | Password-table export to the public web root; bundled Derby freeze until restart | 8.3 / 7.2 | [`sql-selectlimit-injection/`](sql-selectlimit-injection/) |
| [CVE-2026-78224](https://www.cve.org/CVERecord?id=CVE-2026-78224) | XSLT Step XXE | Unauthenticated channel client | OOB read of a target-local file; channel-local slow-entity DoS | 8.2 / 8.8 | [`xslt-step-xxe/`](xslt-step-xxe/) |
| [CVE-2026-82578](https://www.cve.org/CVERecord?id=CVE-2026-82578) | XML Batch Adaptor XXE | Unauthenticated channel client | OOB read of a target-local file | 7.5 / 8.7 | [`xml-batch-xxe/`](xml-batch-xxe/) |

CVSS 3.1 and 4.0 are different standards; the paired scores are not a before-and-after comparison.

All three were reproduced against:

```text
nextgenhealthcare/connect:4.5.2
sha256:4afa295cfe7c5ffd596efee69594157fea87202e33d66bb4a98a52db4598f836
```

NextGen privately reported that the XSLT issue was fixed in 4.7.1 and the SQL injection
and XML Batch issues were fixed in 4.7.2. [CISA advisory
ICSMA-26-253-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-253-01)
treats 4.7.1 and earlier as affected and recommends 4.7.2 or later. Releases after 4.5 are proprietary, so
there is no public fixed image from which this repository can provide the same
kind of reproducible negative control used for an open-source patch release.

## What an attacker gains

### CVE-2026-82583: database and integration-secret exposure

An authenticated foothold on the administrative API becomes access to data the
account was not intended to export. The packaged exploit writes the live
`PERSON_PASSWORD` row beneath `public_html` and proves that the resulting file is
downloadable without authentication. The step that matters is going from a restricted API action to a file on disk that
no longer needs the attacker's session at all.

In a real integration environment, the database can describe channels, endpoints,
and credentials used to reach databases, SFTP servers, mail relays, APIs, and other
clinical systems. A separate controlled test recovered a deliberately planted
connector password from exported channel XML. That makes the primitive useful for
environment mapping and secret theft; use of any recovered credential against a
downstream system was not tested and is not claimed.

The optional denial-of-service arm freezes the bundled Derby database. DB-backed API
calls then time out, the same injection cannot unfreeze its own entrypoint, and a
process restart is required. This is a practical recovery burden for Derby-backed
installations, not proof that external production databases behave the same way.

### CVE-2026-78224: unauthenticated server-file disclosure and channel interruption

Once an affected XSLT channel is deployed, the attacker needs no Mirth account. The
incoming XML makes the service read a target-local file and send its contents to an
attacker-controlled callback. This is useful even when the normal channel response
does not contain the transformed data and the attacker cannot read message history.

The standalone client accepts a caller-selected single-line `file:` URI. Files such
as host identifiers, tokens, configuration fragments, or credentials are practically
valuable if the Mirth service account can read them and the server can reach the
callback. The packaged proof uses only a generated canary and does not claim universal
arbitrary-file recovery, multiline transport, or access beyond the service account.

A slow external entity also occupies the default one-thread victim channel. That can
delay or stop the specific clinical interface mapped to that channel until the entity
is released. The control channel and administrative API remain healthy, so this is
channel-local disruption rather than a whole-server outage.

### CVE-2026-82578: blind file exfiltration through batch input

When an affected XML batch mode is enabled, an unauthenticated sender can use the raw
batch body to trigger the same kind of outbound file disclosure. The server returns
HTTP 500, but the attacker already has the target-only file content through the OOB
callback. That makes the flaw practically useful as a blind exfiltration path even
when response-code-only testing would dismiss the request as a parser failure.

Batch processing is off by default, the split mode must reach the XPath-backed parser,
and server egress is required. This repository does not claim a demonstrated denial
of service for CVE-2026-82578.

## Run

Requirements: Bash, Docker, x86-64 Linux, and network access for the initial image
pull. Both images are digest-pinned. No host port is published; the target and
attacker communicate only on a task-specific internal Docker bridge.

```bash
./run-all.sh
```

Or run a single finding:

```bash
./sql-selectlimit-injection/poc/run.sh
./xslt-step-xxe/poc/run.sh
./xml-batch-xxe/poc/run.sh
```

Each invocation creates uniquely named containers and a bridge network, records
`evidence/current-run.log`, and removes its own lab resources on exit. The checked-in
`evidence/vulnerable-4.5.2.log` files are transcripts from an x86-64 Linux replay.

## What is and is not claimed

- SQL injection is demonstrated through the real REST entrypoint and bundled Derby
  database. The PoC exports the live `PERSON_PASSWORD` row and retrieves the file
  without authentication. Its optional lab arm invokes `SYSCS_FREEZE_DATABASE`,
  after which DB-backed API calls stop responding until the target restarts.
- The XSLT PoC uses a fixed, administrator-installed identity transform. The
  attacker controls only the unauthenticated inbound message. File contents return
  through an external DTD callback. Its standalone client accepts a target-local
  single-line `file:` URI; the lab wrapper uses a random canary and exact assertion.
  The same run proves channel-local unavailability with a healthy second channel
  and admin API, then verifies recovery.
- The XML Batch PoC enables the product's ordinary XML `Element Name` batch mode.
  The attacker controls only the unauthenticated batch body. Its standalone client
  has the same `--file-uri` mode and single-line OOB limitation.
- No downstream healthcare product, patient record, or third-party system was
  tested. References to possible PHI or downstream credentials describe deployment
  consequences, not additional demonstrated victims.
- The export-path candidate in the research checkout is intentionally absent. The
  API is designed for server-side export and the supplied material did not prove a
  portable privilege-boundary violation or a complete code-execution chain.

## Safety

Run only in a disposable lab you own. The SQL PoC deliberately freezes the target
database; recovery requires restarting the target. The XXE PoCs read a mounted
canary by default, but their standalone clients accept arbitrary listener URLs and
single-line target-local file URIs. Never direct them at systems without authorization.

## Mitigation

Per CISA, upgrade to Connect 4.7.2 or later. Where an immediate upgrade is not
possible, restrict the administrative API to trusted management networks, remove
unneeded XSLT steps, disable XML batch processing where it is not required, and
block unnecessary server egress. Those measures reduce exposure but do not repair
the vulnerable code.

## Credit

Findings 1 and 3 should be credited to Abhinav Agarwal. Finding 2 was independently
discovered by Abhinav Agarwal and first reported to NextGen by Youngdu. NextGen
coordinated fixes and CVE assignment.

## Intended defensive use

This repository is intended to help defenders turn advisory text into observable,
testable behavior. In an isolated copy of an environment, defenders can use it to:

- determine whether the public 4.5.2 behavior is present and understand the exact
  configuration prerequisites;
- validate that management-plane controls prevent untrusted accounts from reaching
  the Database Connector operation;
- confirm that egress filtering blocks the tested XXE callback path;
- build detections for suspicious `_getTables` requests, unexpected Derby export or
  freeze procedures, new files beneath `public_html`, inbound XML containing a
  `DOCTYPE`, and Mirth-originated callbacks after listener errors;
- prioritize rotation of connector credentials when an affected administrative plane
  may have been compromised; and
- rerun the same assertions against a vendor-provided fixed build as a local negative
  control, even though that build cannot be distributed here.

Every PoC runs in a container, pins its images by digest, and fails closed unless a
random canary comes back. A defender can reproduce the actual security boundary
rather than take a screenshot or a severity number on faith. It exists to help people
find what they are running, test it, and confirm a patch worked. It is not here to be
pointed at a hospital.
