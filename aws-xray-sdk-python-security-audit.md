# AWS X-Ray SDK for Python - Security Audit Report

**Date:** 2026-02-28
**Target:** [aws-xray-sdk-python](https://github.com/aws/aws-xray-sdk-python) v2.15.0
**Scope:** Full source code review of all modules (104 Python files)

---

## Executive Summary

The AWS X-Ray SDK for Python is a tracing library that instruments applications to send telemetry data to the AWS X-Ray service. This audit reviewed the SDK for security vulnerabilities including injection flaws, information disclosure, insecure defaults, and supply chain risks.

**Project Status:** The AWS X-Ray SDKs entered **maintenance mode on February 25, 2026**. Only critical bug fixes and security updates will be provided. End-of-support is **February 25, 2027**. AWS recommends migrating to **AWS Distro for OpenTelemetry (ADOT)**.

**Key findings:** 19 security issues identified (0 Critical, 3 High, 5 Medium, 7 Low, 4 Informational). The most significant issues relate to inconsistent URL sanitization leaking query parameters with secrets across Django/aiohttp/Bottle middleware, arbitrary code execution via external module patching from the CWD, raw SQL query capture enabled by default, trace header injection enabling cross-service data propagation, and unsigned/unencrypted daemon communication.

**Known CVEs:** No CVE has ever been directly assigned to aws-xray-sdk-python. The historical indirect CVE-2020-22083 (jsonpickle) was remediated in v2.7.0.

---

## Findings

### FINDING-01: Arbitrary Code Execution via External Module Patching from CWD (Medium-High)

**File:** `aws_xray_sdk/core/patcher.py:70-79, 112-128, 205-234`

**Description:** The `patch()` function allows patching of external (non-built-in) modules. For modules not in the `SUPPORTED_MODULES` tuple, `_is_valid_import()` checks if a module exists relative to the current working directory:

```python
def _is_valid_import(module):
    module = module.replace('.', '/')
    realpath = os.path.realpath(module)
    is_module = os.path.isdir(realpath) and (
        os.path.isfile('{}/__init__.py'.format(module)) ...
    )
```

Then `_external_module_patch()` uses `pkgutil.iter_modules()` to walk the filesystem directory for submodules, and `_on_import()` automatically patches all functions and classes in discovered modules. Only a minimal guard exists (rejecting relative imports starting with `.`).

**Impact:** If an attacker can write files to the application's working directory (via file upload vulnerability, shared temp directory, or a compromised dependency) AND influence the `modules_to_patch` list, they achieve arbitrary code execution. The function iterates the filesystem and imports discovered Python files.

---

### FINDING-02: SQL Query Disclosure via "Sanitized" Query Streaming (Medium)

**Files:**
- `aws_xray_sdk/ext/django/db.py:21-26`
- `aws_xray_sdk/ext/sqlalchemy_core/patch.py:45`

**Description:** When `stream_sql=True` (the default), the SDK captures raw SQL query text and labels it `sanitized_query`. Despite the misleading name, no sanitization is performed. The raw query string, which may contain PII, credentials, or other sensitive data embedded in SQL literals, is sent to the X-Ray daemon and stored in AWS X-Ray.

```python
# django/db.py:23 - "sanitized_query" is actually the raw query
self._xray_meta['sanitized_query'] = query
```

**Impact:** Sensitive data in SQL queries (email addresses, passwords in INSERT/UPDATE statements, auth tokens) is exfiltrated to the X-Ray service. Anyone with `xray:BatchGetTraces` IAM permissions can retrieve this data.

**Note:** The SDK does strip passwords from SQLAlchemy database connection URLs (`ext/sqlalchemy/util/decorators.py:105-111`), but this only covers the connection string, not query content.

---

### FINDING-03: Trace Header Injection / Cross-Service Data Propagation (Medium)

**Files:**
- `aws_xray_sdk/core/models/trace_header.py:42-69`
- `aws_xray_sdk/ext/util.py:14-41`

**Description:** The `TraceHeader.from_header_str()` method parses the `X-Amzn-Trace-Id` header from incoming HTTP requests. Any key-value pair in the header that isn't `Root`, `Parent`, `Sampled`, or `Self` is stored in an arbitrary `data` dictionary (line 62) without validation:

```python
# trace_header.py:61-62
elif key != SELF:
    data[key] = entry[1]  # Arbitrary attacker-controlled data stored
```

This data is then propagated to all downstream HTTP requests via `inject_trace_header()` (util.py:14-41), which calls `to_header_str()` re-serializing the arbitrary data into outgoing headers:

```python
# trace_header.py:87-89
if self.data:
    for key in self.data:
        h_parts.append(key + '=' + self.data[key])
```

Neither keys nor values are validated for forbidden characters (newlines, carriage returns, semicolons).

**Impact:**
- Arbitrary key-value pairs propagate across microservices via trace headers
- Enables cross-service data pollution and potential log injection
- Newline characters (`\r\n`) in values could enable HTTP header injection in downstream requests
- No size limits on the data dictionary

**Proof of Concept:**
```
X-Amzn-Trace-Id: Root=1-fake-traceid;Parent=abc123;Sampled=1;Evil=payload;Inject=data
```

---

### FINDING-04: Unauthenticated/Unencrypted HTTP Communication with X-Ray Daemon (Medium)

**File:** `aws_xray_sdk/core/sampling/connector.py:149-156`

**Description:** The `ServiceConnector._create_xray_client()` creates a botocore X-Ray client that communicates over **plain HTTP with no request signing**:

```python
def _create_xray_client(self, ip='127.0.0.1', port='2000'):
    session = botocore.session.get_session()
    url = 'http://%s:%s' % (ip, port)
    return session.create_client('xray', endpoint_url=url,
                                 region_name='us-west-2',
                                 config=Config(signature_version=UNSIGNED),
                                 aws_access_key_id='', aws_secret_access_key='')
```

**Impact:** A network-level MITM attacker could tamper with sampling rules fetched from the daemon, leading to:
- **Denial of observability**: forcing no-sampling to make attacks invisible
- **Data exfiltration**: forcing 100% sampling combined with daemon address redirection
- The `ip` and `port` flow from `AWS_XRAY_DAEMON_ADDRESS` env var without validation

---

### FINDING-05: Path Traversal in Sampling Rules File Loading (Medium)

**File:** `aws_xray_sdk/core/recorder.py:512-521`

**Description:** The `_load_sampling_rules` method accepts a string path and opens it directly without validation:

```python
def _load_sampling_rules(self, sampling_rules):
    if not sampling_rules:
        return
    if isinstance(sampling_rules, dict):
        self.sampler.load_local_rules(sampling_rules)
    else:
        with open(sampling_rules) as f:
            self.sampler.load_local_rules(json.load(f))
```

**Impact:** If an application passes user-controlled input to `xray_recorder.configure(sampling_rules=user_input)`, an attacker could read arbitrary JSON files on the filesystem via path traversal (e.g., `../../../../etc/shadow` won't work, but any valid JSON file would be parsed and its contents potentially reflected in error messages).

---

### FINDING-06: Daemon Address Redirection via Environment Variable (Low)

**Files:**
- `aws_xray_sdk/core/daemon_config.py:24`
- `aws_xray_sdk/core/emitters/udp_emitter.py:63`

**Description:** The daemon address is read from `AWS_XRAY_DAEMON_ADDRESS` with minimal validation (only basic format parsing). All trace data is sent via UDP to the parsed address:

```python
val = os.getenv(DAEMON_ADDRESS_KEY, daemon_address)
# ...later...
self._socket.sendto(data.encode('utf-8'), (self._ip, self._port))
```

No validation that the IP is a valid/expected destination (e.g., localhost or internal address).

**Impact:** Information disclosure of all traced data (URLs, IPs, user agents, SQL queries, exception traces, AWS metadata) to an attacker-controlled endpoint. Particularly impactful in container/serverless environments.

---

### FINDING-07: SDK Disabling via Environment Variable (Low)

**File:** `aws_xray_sdk/sdk_config.py:29-49`

**Description:** `AWS_XRAY_SDK_ENABLED=false` completely disables all tracing silently. The environment variable always overrides programmatic configuration.

**Impact:** "Denial of observability" - tracing becomes invisible to monitoring that relies on X-Ray traces.

---

### FINDING-08: Insecure Temporary File Operations in Lambda (Low)

**File:** `aws_xray_sdk/core/lambda_launcher.py:28-38`

**Description:** Touch file creation at `/tmp/.aws-xray/initialized` uses `os.mkdir()` and `open()` with `'w+'` mode, vulnerable to symlink attacks and TOCTOU race conditions. The file handle is not closed via `with` statement.

**Impact:** Limited file overwrite in Lambda's temp directory via symlink attack.

---

### FINDING-09: Mutable Default Argument Causing Data Leakage (Low)

**File:** `aws_xray_sdk/ext/dbapi2.py:11, 26`

**Description:** Both `XRayTracedConn.__init__` and `XRayTracedCursor.__init__` use `meta={}` as a mutable default argument. The dict is mutated at line 34 (`self._xray_meta['database_type'] = db_type`).

**Impact:** Cross-connection metadata leakage if instances are created without explicit `meta` argument.

---

### FINDING-10: Log Injection via Malformed Trace Headers (Low)

**File:** `aws_xray_sdk/core/models/trace_header.py:72`

**Description:** Malformed trace headers are logged without sanitization:
```python
log.warning("malformed tracing header %s, ignore.", header)
```

**Impact:** Log spoofing via newlines, ANSI escape codes, or control characters in `X-Amzn-Trace-Id` header.

---

### FINDING-11: Full Trace Data Logged at DEBUG Level (Low)

**File:** `aws_xray_sdk/core/emitters/udp_emitter.py:40`

**Description:** The full serialized JSON of segments (including URLs, SQL queries, exception details, working directory) is logged at DEBUG level:
```python
log.debug("sending: %s to %s:%s." % (message, self._ip, self._port))
```

**Impact:** Sensitive trace data exposed if DEBUG logging is enabled in production.

---

### FINDING-12: Working Directory Path Disclosure (Informational)

**File:** `aws_xray_sdk/core/models/entity.py:248`

**Description:** `os.getcwd()` is included in trace data when exceptions occur, revealing server filesystem structure.

---

### FINDING-13: Unencrypted UDP Trace Data Transmission (Informational)

**File:** `aws_xray_sdk/core/emitters/udp_emitter.py`

**Description:** All trace data sent via unencrypted UDP with no TLS option. Network eavesdroppers can capture URLs, IPs, SQL queries, exception traces.

---

### FINDING-14: Inconsistent URL Sanitization - Django/aiohttp/Bottle Leak Query Parameters (High)

**Files WITHOUT sanitization (leak full URL with query params):**
- `aws_xray_sdk/ext/django/middleware.py:75` - `request.build_absolute_uri()` includes query string
- `aws_xray_sdk/ext/aiohttp/middleware.py:47` - `str(request.url)` includes query string
- `aws_xray_sdk/ext/bottle/middleware.py:58` - `request.url` includes query string

**Files WITH proper sanitization (strip query params):**
- `aws_xray_sdk/ext/requests/patch.py:51` - uses `strip_url()`
- `aws_xray_sdk/ext/httplib/patch.py:54` - uses `strip_url()`
- `aws_xray_sdk/ext/httpx/patch.py:42` - uses `copy_with(query=None, fragment=None)`
- `aws_xray_sdk/ext/flask/middleware.py:58` - uses `req.base_url` (excludes query string)

**Description:** Three of the server-side middleware implementations (Django, aiohttp, Bottle) record the complete request URL including query parameters in traces. Other extensions in the same SDK strip query parameters. This inconsistency means query parameters containing API keys, tokens, session IDs, password reset codes, and PII are captured and stored in X-Ray.

In Django middleware, the full URL is also stored as a searchable **annotation** (line 78):
```python
segment.put_annotation(http.URL, request.build_absolute_uri())
```
Annotations are indexed, making sensitive query parameters even more exposed.

**Impact:** Secrets in query parameters (`?token=xxx`, `?api_key=yyy`, `?reset_code=zzz`) are stored in X-Ray traces. Anyone with `xray:BatchGetTraces` or X-Ray Console access can retrieve them.

---

### FINDING-15: MongoDB Full Document Capture Leaks Business Data (Medium)

**File:** `aws_xray_sdk/ext/pymongo/patch.py:32-33, 39`

**Description:** The pymongo patch has `record_full_documents` option. When enabled, complete MongoDB commands and replies are recorded:
```python
subsegment.put_metadata('mongodb_command', event.command)
subsegment.put_metadata('mongodb_reply', event.reply)
```
Even with default `False`, failure details are always recorded unconditionally:
```python
subsegment.put_metadata('failure', event.failure)
```
MongoDB error messages can contain query details, authentication failures, and sensitive data.

---

### FINDING-16: psycopg2 DSN Parsing May Expose Database Password (Low)

**Files:**
- `aws_xray_sdk/ext/psycopg2/patch.py:35`
- `aws_xray_sdk/ext/psycopg/patch.py:23`

**Description:** DSN parsing constructs a dict from the connection's DSN string which may include the password field in older psycopg2 versions (pre-2.7). While not directly sent to X-Ray in current code, the parsed dict is available in scope.

---

### FINDING-17: SQLAlchemy Global Parent Class Monkey-Patching (Low)

**File:** `aws_xray_sdk/ext/sqlalchemy/util/decorators.py:11-24`

**Description:** The `decorate_all_functions` decorator patches methods on the **parent** SQLAlchemy classes (`Session`, `Query`) rather than the child X-Ray classes:
```python
for c in cls.__bases__:
    ...
    setattr(c, name, function_decorator(c, obj))  # patches parent!
```
This globally modifies all SQLAlchemy sessions and queries, even non-X-Ray-wrapped ones. Could interfere with security-relevant SQLAlchemy behavior.

---

### FINDING-18: X-Forwarded-For Header Trust Without Validation (Informational)

**Files:**
- `aws_xray_sdk/ext/django/middleware.py:85-91`
- `aws_xray_sdk/ext/flask/middleware.py:62-67`
- `aws_xray_sdk/ext/bottle/middleware.py:62`

**Description:** Trivially spoofable `X-Forwarded-For` headers are stored directly in trace data as client IPs. Bottle middleware additionally sets `X_FORWARDED_FOR=True` even when using `REMOTE_ADDR`.

---

### FINDING-19: Historical jsonpickle Deserialization Vulnerability (Informational - Fixed)

**Reference:** CHANGELOG.rst; CVE-2020-22083

**Description:** The SDK previously used jsonpickle (vulnerable to RCE via `decode()`). The SDK only used `encode()` so was not directly exploitable. Remediated in v2.7.0 by replacing with standard `json`.

---

## Dependency Analysis

| Dependency | Constraint | Known CVEs | Risk |
|---|---|---|---|
| **wrapt** | Unpinned (any) | None | Low |
| **botocore** | >=1.11.3 | None direct; urllib3 CVE-2025-50182 (Pyodide only) | Low |

---

## Security-Related Changelog Entries

| Version | Change | Relevance |
|---|---|---|
| 2.15.0 | Fix log stack overflow from circular reference metadata | DoS mitigation |
| 2.7.0 | Replace jsonpickle with json (PR #275) | CVE-2020-22083 remediation |
| 2.6.0 | IMDSv2 support for EC2 plugin (PR #226) | SSRF hardening |
| 2.4.0 | Strip password from SQLAlchemy URLs (PR #132) | Credential leak prevention |

---

## Security Testing Gaps

- No dedicated security test suite or fuzzing
- No SAST integration (bandit, semgrep)
- No dependency vulnerability scanning (pip-audit, safety)
- Missing SECURITY.md / vulnerability reporting process

---

## Positive Security Practices

- Entity names sanitized of special characters (`entity.py:38`)
- Annotation keys validated against character whitelist (`entity.py:150`)
- AWS namespace prefix reserved/blocked for metadata (`entity.py:172`)
- Secure random ID generation via `os.urandom()` (`entity.py:313`)
- Thread-safe counters/reservoirs using `threading.Lock()`
- jsonpickle removed in favor of safe `json` serialization
- Password stripping from SQLAlchemy connection URLs

---

## Attack Surface Summary

1. **Incoming HTTP headers** (`X-Amzn-Trace-Id`) - parsed, stored, propagated to downstream services
2. **Environment variables** - control daemon address, SDK enable/disable, service names, sampling
3. **Module patching** - imports and instruments arbitrary Python modules from filesystem
4. **Configuration** - sampling rules file path traversal, dynamic plugin loading
5. **Network** - unencrypted/unsigned communication with X-Ray daemon over UDP/HTTP
6. **Data exfiltration** - trace data sent to external service includes URLs, IPs, SQL queries, stack traces

---

## Recommendations

1. **Restrict external module patching** - validate module names against an allowlist or require explicit opt-in for CWD-based module loading
2. **Sanitize SQL queries** before inclusion in traces, or default `stream_sql` to `False`
3. **Validate trace header data fields** - restrict characters, enforce size limits, strip newlines
4. **Add TLS/signing option** for daemon communication
5. **Fix mutable default arguments** in `dbapi2.py`
6. **Sanitize logged values** from user-controlled headers
7. **Validate sampling rules path** against a configured base directory
8. **Document security implications** of enabling SQL streaming and full URL capture
9. **Plan migration to OpenTelemetry** before Feb 2027 EOL

---

*This audit was conducted through static analysis of the source code. Dynamic testing may reveal additional vulnerabilities.*
