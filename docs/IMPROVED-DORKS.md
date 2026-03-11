# Better Code Search Queries for Vulnerability Hunting

These queries are designed for **higher signal bug hunting**, targeting patterns that frequently surface real vulnerabilities during manual review and bug bounty work.

They emphasize:

- Direct **source → sink relationships**
- Dangerous **framework behaviours**
- **RCE / deserialization / file access** first
- **API-heavy backend code**

Languages covered:

- PHP
- JavaScript / Node.js
- Java (Spring-heavy patterns)
- .NET / ASP.NET
- Python (Flask / Django style patterns)

These assume **GitHub Code Search regex behaviour (line-based)**.

---

# Global Noise Reduction Filters

Append to most queries when automating:

```text
NOT path:test
NOT path:tests
NOT path:spec
NOT path:vendor
NOT path:node_modules
NOT path:dist
NOT path:build
NOT path:migrations
NOT path:fixtures
```

```text
stars:>100
```

---

# PHP (20)

## Command Injection

```
language:php /\b(exec|system|shell_exec|passthru)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)/
language:php /\bpopen\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\bproc_open\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\bexec\s*\([^)]*\$[A-Za-z0-9_]+\s*\.\s*\$_(GET|POST|REQUEST)/
```

## File Inclusion / Path Traversal

```
language:php /\b(include|require|include_once|require_once)\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /file_get_contents\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /fopen\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /readfile\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /glob\s*\([^)]*\$_(GET|POST|REQUEST)/
```

## Deserialization / Object Injection

```
language:php /\bunserialize\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)/
language:php /\bunserialize\s*\(\s*base64_decode\s*\(/ 
language:php /\bunserialize\s*\(\s*gzinflate\s*\(/ 
```

## Dangerous Eval

```
language:php /\beval\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\bassert\s*\([^)]*\$_(GET|POST|REQUEST)/
```

## SQL Injection

```
language:php /mysqli_query\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /PDO::query\s*\([^)]*\$_(GET|POST|REQUEST)/
language:php /\->query\s*\([^)]*\$_(GET|POST|REQUEST)/
```

---

# JavaScript / Node.js (20)

## Command Injection

```
language:javascript /child_process\.(exec|execSync|spawn)\s*\([^)]*req\.(query|body|params)/
language:javascript /\bexec\s*\([^)]*req\.(query|body|params)/
language:javascript /\bspawn\s*\([^)]*req\.(query|body|params)/
```

## Path Traversal / File Read

```
language:javascript /fs\.readFile\s*\([^)]*req\.(query|params)/
language:javascript /fs\.readFileSync\s*\([^)]*req\.(query|params)/
language:javascript /res\.sendFile\s*\([^)]*req\.(query|params)/
language:javascript /path\.join\s*\([^)]*req\.(query|params)/
```

## SSRF

```
language:javascript /axios\.(get|post)\s*\([^)]*req\.(query|body|params)/
language:javascript /fetch\s*\([^)]*req\.(query|body|params)/
language:javascript /request\s*\([^)]*req\.(query|body|params)/
language:javascript /got\s*\([^)]*req\.(query|body|params)/
```

## Dangerous Dynamic Code

```
language:javascript /\beval\s*\([^)]*req\.(query|body|params)/
language:javascript /\bFunction\s*\([^)]*req\.(query|body|params)/
```

## Authentication / Logic

```
language:javascript /jwt\.verify\s*\([^)]*req\.(query|body|params)/
language:javascript /res\.redirect\s*\([^)]*req\.(query|body|params)/
```

---

# Java (15)

## Command Injection

```
language:java /Runtime\.getRuntime\(\)\.exec\s*\([^)]*getParameter/
language:java /ProcessBuilder\s*\([^)]*getParameter/
```

## SQL Injection

```
language:java /Statement\.executeQuery\s*\([^)]*getParameter/
language:java /Statement\.execute\s*\([^)]*getParameter/
language:java /prepareStatement\s*\([^)]*\+[^)]*getParameter/
```

## File Access

```
language:java /new File\s*\([^)]*getParameter/
language:java /FileInputStream\s*\([^)]*getParameter/
language:java /Files\.readAllBytes\s*\([^)]*getParameter/
```

## Redirect / SSRF

```
language:java /sendRedirect\s*\([^)]*getParameter/
language:java /URL\s*\(\s*request\.getParameter/
```

## Deserialization

```
language:java ObjectInputStream.readObject
language:java XMLDecoder
```

---

# .NET / C# (15)

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

## Host Header Injection

```
language:csharp Request.Headers["Host"]
language:csharp Request.Host.Value
```

---

# Python (15)

## Command Injection

```
language:python /os\.system\s*\([^)]*request/
language:python /subprocess\.(Popen|call|run)\s*\([^)]*request/
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
language:python /requests\.(get|post)\s*\([^)]*request/
language:python /urllib\.request\.urlopen\s*\([^)]*request/
```

## File Access

```
language:python /open\s*\([^)]*request/
language:python /send_file\s*\([^)]*request/
```

## Dangerous Execution

```
language:python /\beval\s*\([^)]*request/
language:python /\bexec\s*\([^)]*request/
```

---

# Cross-Language High-Signal Queries (10)

These often surface critical issues regardless of language.

```
/unserialize\s*\(/
/child_process\.exec/
/Runtime\.getRuntime\(\)\.exec/
/pickle\.loads/
/yaml\.load/
/Process\.Start/
/eval\s*\(/
/exec\s*\(/
/HTTP_HOST/
/req\.headers\.host/
```

---

# In order

1. Command injection
2. Deserialization
3. File access / path traversal
4. SQL injection
5. SSRF
6. Redirect / logic bugs

---

# Notes

- GitHub regex searches operate **line-by-line**
- Avoid relying on multiline taint flows
- Focus on **direct sinks**
- Combine with **path heuristics** for better results:

```
path:/admin|internal|debug|test|dev/
path:/upload|import|backup/
path:/reset|forgot|password/
path:/api/
```
