# GitHub Code Search Security Dorks

This document contains a curated list of GitHub Code Search queries designed to identify potentially vulnerable code patterns across common backend languages.

Languages covered:

- PHP
- JavaScript / Node.js
- Java
- .NET / C#
- Python

These queries are optimized for **single-line matching**, as GitHub Code Search regex operates primarily on a line-by-line basis.

---

# Recommended Global Filters

To reduce noise during automation, append the following filters to most searches:

```text
NOT path:test
NOT path:tests
NOT path:spec
NOT path:vendor
NOT path:node_modules
NOT path:dist
NOT path:build
```

---

# PHP

## XSS

```
language:php /\becho\s+[^;\n]*\$_(GET|POST|REQUEST)/
language:php /\bprint\s+[^;\n]*\$_(GET|POST|REQUEST)/
language:php /\bprintf\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /<\?=\s*\$_(GET|POST|REQUEST)/
language:php /\becho\s+[^;\n]*\$_COOKIE/
```

## SQL Injection

```
language:php /mysqli_query\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /mysql_query\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\->query\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\->exec\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /PDO::query\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\bSELECT\b[^;\n]*\$_(GET|POST|REQUEST)/
language:php /\bINSERT\b[^;\n]*\$_(GET|POST|REQUEST)/
```

## Command Injection

```
language:php /\bexec\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\bsystem\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\bshell_exec\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\bpassthru\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\bpopen\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\bproc_open\s*\([^)]*\$_(GET|POST|REQUEST)/
```

## File Inclusion / Path Traversal

```
language:php /\binclude\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\brequire\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /file_get_contents\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /readfile\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /fopen\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /file_put_contents\s*\([^)]*\$_(GET|POST|REQUEST)/
```

## Deserialization

```
language:php /\bunserialize\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\bjson_decode\s*\([^)]*\$_(GET|POST|REQUEST)/
```

## File Upload

```
language:php /move_uploaded_file\s*\([^)]*\$_FILES/
language:php /\$_FILES\[[^\]]+\]\['name'\]/
language:php /\$_FILES\[[^\]]+\]\['tmp_name'\]/
```

## SSRF

```
language:php /curl_setopt\s*\([^)]*CURLOPT_URL[^)]*\$_(GET|POST|REQUEST)/
language:php /file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)/
```

## Open Redirect

```
language:php /header\s*\(\s*["']Location:[^"]*\$_(GET|POST|REQUEST)/
```

## Host Header

```
language:php /\$_SERVER\[['"]HTTP_HOST['"]\]/
language:php /\$_SERVER\[['"]SERVER_NAME['"]\]/
```

---

# JavaScript / Node.js

## XSS

```
language:javascript /res\.send\s*\([^)]*req\.(query|body|params)/
language:javascript /res\.write\s*\([^)]*req\.(query|body|params)/
language:javascript /innerHTML\s*=\s*[^;]*location/
language:javascript /document\.write\s*\([^)]*location/
language:javascript /dangerouslySetInnerHTML/
```

## Command Injection

```
language:javascript /child_process\.exec\s*\([^)]*req\.(query|body|params)/
language:javascript /child_process\.execSync\s*\([^)]*req\.(query|body|params)/
language:javascript /child_process\.spawn\s*\([^)]*req\.(query|body|params)/
language:javascript /exec\s*\([^)]*req\.(query|body|params)/
```

## SSRF

```
language:javascript /axios\.get\s*\([^)]*req\.(query|body|params)/
language:javascript /axios\.post\s*\([^)]*req\.(query|body|params)/
language:javascript /request\s*\([^)]*req\.(query|body|params)/
language:javascript /fetch\s*\([^)]*req\.(query|body|params)/
language:javascript /got\s*\([^)]*req\.(query|body|params)/
```

## Path Traversal

```
language:javascript /fs\.readFile\s*\([^)]*req\.(query|params)/
language:javascript /fs\.readFileSync\s*\([^)]*req\.(query|params)/
language:javascript /res\.sendFile\s*\([^)]*req\.(query|params)/
language:javascript /path\.join\s*\([^)]*req\.(query|params)/
language:javascript /path\.resolve\s*\([^)]*req\.(query|params)/
```

## Redirect

```
language:javascript /res\.redirect\s*\([^)]*req\.(query|body|params)/
```

## Host Header

```
language:javascript /req\.headers\.host/
language:javascript /req\.get\(['"]host['"]\)/
```

## Dangerous JavaScript

```
language:javascript /\beval\s*\([^)]*req\.(query|body|params)/
language:javascript /\bFunction\s*\([^)]*req\.(query|body|params)/
```

---

# Java

## SQL Injection

```
language:java /Statement\.executeQuery\s*\([^)]*getParameter/
language:java /Statement\.execute\s*\([^)]*getParameter/
language:java /createStatement\s*\([^)]*getParameter/
language:java /prepareStatement\s*\([^)]*\+[^)]*getParameter/
```

## Command Injection

```
language:java /Runtime\.getRuntime\(\)\.exec\s*\([^)]*getParameter/
language:java /ProcessBuilder\s*\([^)]*getParameter/
```

## File Handling

```
language:java /new File\s*\([^)]*getParameter/
language:java /FileInputStream\s*\([^)]*getParameter/
language:java /Files\.readAllBytes\s*\([^)]*getParameter/
```

## Redirect

```
language:java /sendRedirect\s*\([^)]*getParameter/
language:java /response\.sendRedirect\s*\([^)]*request/
```

## Deserialization

```
language:java ObjectInputStream.readObject
language:java /readObject\s*\(/
language:java XMLDecoder
```

---

# .NET / C#

## SQL Injection

```
language:csharp /SqlCommand\s*\([^)]*Request\.(Query|Form)/
language:csharp /ExecuteReader\s*\([^)]*Request\.(Query|Form)/
language:csharp /ExecuteNonQuery\s*\([^)]*Request\.(Query|Form)/
```

## Command Injection

```
language:csharp /Process\.Start\s*\([^)]*Request\.(Query|Form)/
language:csharp /ProcessStartInfo\s*\([^)]*Request\.(Query|Form)/
```

## File Access

```
language:csharp /File\.ReadAllText\s*\([^)]*Request\.(Query|Form)/
language:csharp /FileStream\s*\([^)]*Request\.(Query|Form)/
```

## Redirect

```
language:csharp /Response\.Redirect\s*\([^)]*Request\.(Query|Form)/
language:csharp /Redirect\s*\([^)]*Request\.(Query|Form)/
```

## Host Header

```
language:csharp Request.Headers["Host"]
language:csharp Request.Host.Value
language:csharp HttpContext.Request.Host
```

---

# Python

## Command Injection

```
language:python /os\.system\s*\([^)]*request/
language:python /subprocess\.Popen\s*\([^)]*request/
language:python /subprocess\.call\s*\([^)]*request/
language:python /subprocess\.run\s*\([^)]*request/
```

## Deserialization

```
language:python pickle.loads
language:python /pickle\.loads\s*\([^)]*request/
language:python yaml.load
language:python /yaml\.load\s*\([^)]*request/
```

## SSRF

```
language:python /requests\.get\s*\([^)]*request/
language:python /requests\.post\s*\([^)]*request/
language:python /urllib\.request\.urlopen\s*\([^)]*request/
```

## Path Traversal

```
language:python /open\s*\([^)]*request/
language:python /send_file\s*\([^)]*request/
language:python /FileResponse\s*\([^)]*request/
```

## Dangerous Python

```
language:python /\beval\s*\([^)]*request/
language:python /\bexec\s*\([^)]*request/
language:python DEBUG\s*=\s*True
```

---

# Cross-Language High-Signal Queries

```
/unserialize\s*\(/
/child_process\.exec/
/Runtime\.getRuntime\(\)\.exec/
/pickle\.loads/
/yaml\.load/
/Process\.Start/
/res\.redirect\s*\([^)]*req\.query/
/header\s*\(["']Location/
/req\.headers\.host/
/HTTP_HOST/
```

---

# Suggested Automation Priority

When scanning repositories automatically, prioritize query execution in the following order:

1. Command Injection
2. Deserialization
3. File Inclusion / Path Traversal
4. SQL Injection
5. SSRF
6. XSS

These categories statistically surface **high-severity vulnerabilities (RCE, file access)** more often than client-side issues.

---

# Notes

- GitHub regex searches operate **per line**, not multi-line.
- Prefer **sink detection** over generic keyword searches.
- Add **language filters** whenever possible.
- Apply **noise filters** (`NOT path:`) globally.
- Run **high-signal queries first** to triage results quickly.

```
