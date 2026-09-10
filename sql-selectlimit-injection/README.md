# CVE-2026-82583: `_getTables` `selectLimit` SQL injection

**CVSS 3.1:** 8.3 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H`)

**CVSS 4.0:** 7.2 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N`)

**CWE:** CWE-89

**Tested:** NextGen Connect 4.5.2

**CISA guidance:** Mirth Connect 4.7.1 and earlier are affected; update to 4.7.2 or later.

The Database Connector metadata endpoint accepts a caller-controlled `selectLimit`
string, substitutes table names into it, and executes the resulting text through a
plain JDBC `Statement`. The operation has no permission attribute of its own.

Against the bundled Derby database, stored procedures execute before
`executeQuery()` rejects the lack of a result set. The PoC uses that behavior to:

1. call `SYSCS_UTIL.SYSCS_EXPORT_QUERY` against the live password table;
2. write the result beneath `public_html`;
3. fetch the exported credential row without authentication; and
4. in the disposable-lab arm, call `SYSCS_FREEZE_DATABASE`, blocking DB-backed
   operations until restart.

This is not a generic “arbitrary SQL means RCE” claim. DDL, DML, Derby JAR install,
and database-property changes were tested separately and did not persist because
their transactions never commit. The demonstrated high impact is data disclosure
plus loss of bundled-Derby-backed operations until restart, not Java code execution.

## Practical attacker value

The PoC turns an authenticated administrative foothold into an export that can be
retrieved without the original session. Beyond password hashes, Mirth's configuration
database can expose channel definitions, endpoint locations, and connector secrets.
A separate controlled run recovered a deliberately planted connector password from
exported channel XML. In a real deployment, that information can help an attacker map
trusted integrations and steal credentials for downstream databases, file-transfer
servers, mail relays, APIs, or clinical systems. No downstream credential was used in
this research, so lateral movement remains a deployment consequence rather than an
additional demonstrated exploit.

The optional freeze arm creates a recovery problem: database-backed requests stop,
the vulnerable entrypoint cannot reach an unfreeze call, and an operator must restart
the target. This result is specific to the bundled Derby database and should not be
generalized to external production databases without separate testing.

## Reproduce

```bash
./poc/run.sh
```

Against an already running authorized target, the standalone exploit accepts a
target URL and ordinary authenticated API credentials:

```bash
python3 poc/exploit.py \
  --target https://target.example:8443 \
  --username api-user \
  --password 'password'
```

Add `--confirm-dos` only in a disposable lab; it freezes the embedded Derby
database and the standalone process cannot restart the target for recovery.

The harness starts a fresh official 4.5.2 container and passes `--confirm-dos` to
the exploit. It requires a healthy DB baseline, an anonymously fetched live password
row, three post-freeze DB timeouts, a responsive non-DB control, failure to unfreeze
through the blocked entrypoint, and DB recovery after restarting the target.

## Source

- [`DatabaseConnectorServlet.java` lines 167-181](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/connectors/jdbc/DatabaseConnectorServlet.java#L167-L181)
- [`DatabaseConnectorServletInterface.java` lines 45-63](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/connectors/jdbc/DatabaseConnectorServletInterface.java#L45-L63)
- [`DefaultAuthorizationController.java` lines 40-46](https://github.com/nextgenhealthcare/connect/blob/6ce3a9f0e3d84841f0b1e07c2808cf0bdb3d0a78/server/src/com/mirth/connect/server/controllers/DefaultAuthorizationController.java#L40-L46)

The PoC uses `admin/admin` only to make the stock-image replay self-contained.
Formally, authentication is required. Authorization extensions in commercial
deployments may impose controls not present in the open-source build.

## Defensive use

Defenders can use the harness in a disposable environment to verify administrative
API reachability, detect suspicious `_getTables` parameters and Derby system routines,
watch for unexpected exports beneath `public_html`, test recovery procedures, and run
the same assertions against a vendor-provided fixed build. If exposure is suspected,
review access logs and rotate connector credentials stored in affected channel
configuration.
