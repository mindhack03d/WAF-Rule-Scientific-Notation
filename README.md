# WAF-Rule-Scientific-Notation

## Description
A Scientific Notation Bug in MySQL left AWS WAF Clients Vulnerable to SQL Injection
### Reference
https://www.gosecure.net/blog/2021/10/19/a-scientific-notation-bug-in-mysql-left-aws-waf-clients-vulnerable-to-sql-injection/
## WAF Rule Scientific Notation
```
# A Scientific Notation Bug in MySQL left AWS WAF Clients Vulnerable to SQL Injection
# https://www.gosecure.net/blog/2021/10/19/a-scientific-notation-bug-in-mysql-left-aws-waf-clients-vulnerable-to-sql-injection/
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "(?i:(.{1,1})?\'\s+(or|and|xor|in)\s+(\')?((\d{1,100}\.(\d{1,100})?e\((true|false|\d{1,100})\))?(true|false)?(.{1,50})?=)?\'(.{1,1})?)" \
        "id:1922200,\
        phase:2,\
        deny,\
        rev:'1',\
        capture,\
        t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,\
        severity:'CRITICAL',\
        auditlog,log,\
        msg:'SQL Injection Attack Detected via Scientific Notation (gosecure)',\
        logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
        tag:'Vulnerability',\
        tag:'application-multi',\
        tag:'language-multi',\
        tag:'platform-multi',\
        tag:'attack-sqli',\
        tag:'paranoia-level',\
        ver:'OWASP_CRS/3.3.2'"
```
## Proof Of Concept
1. Go to apache `conf-enabled`.
```
$ sudo cd /etc/apache2/conf-enabled
```
2. Create the file `sql_scientific_notation.conf`
```
$ sudo vim sql_scientific_notation.conf
```
3. Copy and paste the rule.
4. Reload apache.
```
$ sudo service apache2 restart
```
## Demo
Once the rule was added to apache2, the scientific notation is blocked by WAF.
Run the `wafparao01d3.py`. https://github.com/alt3kx/wafparan01d3
```
$ sudo python3 wafparan01d3.py --run --proxy http://192.168.56.1:8081 --pl 1
```
![wafparan01d3_block](https://user-images.githubusercontent.com/82916147/142824928-3684abb5-1972-46a9-b91e-e7127af73ba3.gif)
### Authors
Alex Hernandez aka <em><a href="https://twitter.com/_alt3kx_" rel="nofollow">(@\_alt3kx\_)</a></em></br>
Jesus Huerta aka <em><a href="https://github.com/mindhack03d" rel="nofollow">@mindhack03d</em> </a>
