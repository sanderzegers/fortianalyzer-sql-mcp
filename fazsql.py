#!/usr/bin/env python3
"""Read-only SQL against a FortiAnalyzer's log database over HTTPS (GUI dataset-test API).

Uses the same internal endpoints as the GUI's dataset "Test" button, so the dataset
macros ($log, $log-<type>, $filter) work. These endpoints are not part of the
documented /jsonrpc API and may change between firmware versions.

Flow: POST /cgi-bin/module/flatui_auth (login, sets CURRENT_SESSION + HTTP_CSRF_TOKEN)
      POST /p/report/dataset/sql/run/       -> request id
      GET  /p/report/dataset/sql/fetch/     -> {"status":"running"} | {"detail":{cells}} | {"error":..}
      GET  /p/report/dataset/sql/cancel/    -> frees a running query
      GET  /p/report/dataset/logtypechoices/ -> log types available per device type

Backend limits (observed): a fetch returns at most 100 rows (flagged `truncated`), results
are single-shot (the request id is freed after the first successful fetch), and an explicit
SQL LIMIT does not raise the cap. Use GROUP BY / ORDER BY / LIMIT to get what you need in
one page rather than paging.

Configuration (environment, or a .env file next to this script; FAZ_ENV_FILE points to
another file, e.g. one per ADOM. Real environment variables take precedence):
  FAZ_HOST       https://faz.example.com           (required)
  FAZ_USER        account name                       (required)
  FAZ_PASSWORD    password; the CLI prompts if unset
  FAZ_ADOM        ADOM to work in, by name. Queries run in the session's ADOM; the tool
                  switches to it at login and errors out if it can't (never silently
                  queries another ADOM). Report-only accounts cannot list ADOMs, so the id
                  is discovered by trying the ADOM ids found in devtable_ext (only ADOMs
                  containing registered devices can be found this way).
  FAZ_ADOM_OID    numeric ADOM id; skips the discovery. Combined with FAZ_ADOM, the name
                  is verified after the switch.
  FAZ_CA_BUNDLE   PEM file to trust instead of the system store
  FAZ_INSECURE=1  disable TLS verification (lab only; same as --insecure)

Use a dedicated account with only the report viewer / run report rights.

CLI:
  fazsql.py --dev fortigate --period 7d "select ... from $log-dns where $filter ..."
  fazsql.py --period custom --start=-24h "select ..."
  fazsql.py --list-types [--dev fortigate]
  fazsql.py --columns dns [--dev fortigate]
Library:
  with FazSql() as faz:
      r = faz.query("select count(*) as n from $log-dns where $filter")
"""
import argparse
import contextlib
import csv
import getpass
import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

def load_env_file(path=None):
    """Fill os.environ from a KEY=VALUE file; variables already set win.

    Default path: FAZ_ENV_FILE, else .env next to this script (not the cwd, which is
    unpredictable when an MCP client launches the server).
    """
    path = path or os.environ.get('FAZ_ENV_FILE') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '.env')
    try:
        with open(path, encoding='utf-8-sig') as f:
            lines = f.read().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key, value = key.strip(), value.strip()
        if key.startswith('export '):
            key = key[7:].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        os.environ.setdefault(key, value)


load_env_file()

ROW_CAP = 100  # rows per fetch the backend returns, regardless of SQL LIMIT

# dev-type numbers (same as the documented API's `devtype`)
DEVTYPES = {
    'fortigate': 0, 'fortimanager': 1, 'syslog': 2, 'forticlient': 3, 'fortimail': 4,
    'fortiweb': 5, 'forticache': 6, 'fortianalyzer': 7, 'fortisandbox': 10,
    'fortiddos': 11, 'fortiauthenticator': 12, 'fortiproxy': 15, 'fabric': 16,
    'fortinac': 17, 'siem': 18, 'fortideceptor': 19, 'fortiadc': 20, 'fortifirewall': 21,
    'fortindr': 22, 'fortisoar': 23, 'fortiisolator': 24, 'fortiedr': 25, 'fortipam': 26,
    'forticasb': 27, 'fortitoken': 28,
}
# log-type numbers (GUI FAZ_SYNTAX.LOGTYPE_*), keyed by the ids the logtypechoices API uses
LOGTYPES = {
    'app-ctrl': 0, 'attack': 1, 'content': 2, 'dlp': 3, 'emailfilter': 4, 'event': 5,
    'generic': 6, 'history': 7, 'im': 8, 'sniffer': 9, 'traffic': 10, 'virus': 11,
    'voip': 12, 'webfilter': 13, 'netscan': 14, 'fct-event': 15, 'fct-traffic': 16,
    'fct-netscan': 17, 'waf': 18, 'gtp': 19, 'dns': 20, 'ssh': 21, 'ssl': 22,
    'file-filter': 23, 'asset': 24, 'protocol': 25, 'siem': 26, 'ztna': 27,
    'security': 28, 'local-event': 33,
}
# period-type numbers (GUI dataset test)
PERIODS = {
    'today': 0, 'yesterday': 1, 'last-n-hours': 2, 'this-week': 3, 'last-week': 4,
    '7d': 5, 'last-n-days': 6, '2w': 7, '14d': 8, 'this-month': 9, 'last-month': 10,
    '30d': 11, 'last-n-weeks': 12, 'this-quarter': 13, 'last-quarter': 14,
    'this-year': 15, 'custom': 16,
}
PERIOD_NEEDS_N = {2, 6, 12}
PERIOD_CUSTOM = 16
# Spellings of "the last N hours/days/weeks" that aren't period names: '90d', '12h', '3w',
# 'last-3-days', 'last 3 weeks', 'last-n-days 3'. Names in PERIODS (7d, 14d, 30d, 2w) win.
_LAST_N_SPELLINGS = (
    re.compile(r'^(?P<n>\d+)(?P<unit>[hdw])$'),
    re.compile(r'^last-(?P<n>\d+)-(?P<unit>hour|day|week)s?$'),
    re.compile(r'^last-n-(?P<unit>hour|day|week)s?-(?P<n>\d+)$'),
)
_LAST_N_PERIOD = {'h': 'last-n-hours', 'd': 'last-n-days', 'w': 'last-n-weeks'}
# custom start/end may be relative to the FAZ clock: 'now', '-90m', '-24h', '-7d', '-2w'
_RELATIVE = re.compile(r'^(?:now|-(\d+)([mhdw]))$')
_UNIT_SECONDS = {'m': 60, 'h': 3600, 'd': 86400, 'w': 604800}
_ABSOLUTE = re.compile(r'^\d{1,2}:\d{2} \d{4}/\d{1,2}/\d{1,2}$')

# `$log-<name>` macros whose name differs from the log type id
MACRO_ALIASES = {'ips': 'attack'}
_LOG_MACRO = re.compile(r'\$log-([a-z][a-z0-9-]*)')
# Tables with a `$log-<name>` macro that the log-type list doesn't name (FortiSandbox). The API
# still needs a log type the device offers; the macro in the SQL picks the table.
UNLISTED_LOGS = {'malware', 'netalert'}


def infer_log_type(sql):
    """Log type named by the first known `$log-<type>` macro in the SQL, else None."""
    for name in _LOG_MACRO.findall(sql):
        name = MACRO_ALIASES.get(name, name)
        if name in LOGTYPES or name in UNLISTED_LOGS:
            return name
    return None


def normalize_period(period, last_n):
    """Turn '90d', '12h', 'last-3-weeks' and similar into (last-n-* period, N)."""
    v = str(period).strip().lower().replace('_', '-').replace(' ', '-')
    if isinstance(period, int) or v.isdigit() or v in PERIODS:
        return period, last_n
    for pattern in _LAST_N_SPELLINGS:
        m = pattern.match(v)
        if m:
            n = int(m.group('n'))
            if last_n and last_n != n:
                raise FazError('period %r and last_n=%d disagree' % (period, last_n))
            return _LAST_N_PERIOD[m.group('unit')[0]], n
    return period, last_n


_FORBIDDEN = re.compile(
    r'\b(insert|update|delete|drop|alter|create|truncate|attach|detach|rename|grant|revoke|'
    r'optimize|kill|system|set|use)\b', re.I)


# Comments, string literals and quoted identifiers, matched in one pass so that e.g. a '--'
# inside a string is not mistaken for a comment that hides the rest of the line.
_SQL_TOKEN = re.compile(r"/\*.*?\*/|--[^\n]*|'(?:[^'\\]|\\.|'')*'|`[^`]*`|\"[^\"]*\"", re.S)


def _blank_token(m):
    return {'/': ' ', '-': ' ', "'": "''"}.get(m.group(0)[0], '``')


class FazError(RuntimeError):
    pass


class FazCancelled(FazError):
    pass


def _resolve(value, table, what):
    """Accept a name (case-insensitive) or a number; return the number."""
    if isinstance(value, int):
        return value
    v = str(value).strip().lower().replace('_', '-')
    if v.isdigit():
        return int(v)
    for key, num in table.items():
        if key.replace(' ', '') == v.replace(' ', ''):
            return num
    raise FazError('unknown %s %r (known: %s)' % (what, value, ', '.join(sorted(table))))


def check_read_only(sql):
    """Client-side guard (defence in depth; the server has its own blocklist)."""
    body = _SQL_TOKEN.sub(_blank_token, sql).strip().rstrip(';').strip()
    if ';' in body:
        raise FazError('only a single statement is allowed')
    if not re.match(r'(select|with)\b', body, re.I):
        raise FazError('only SELECT / WITH queries are allowed')
    m = _FORBIDDEN.search(body)
    if m:
        raise FazError('keyword %r is not allowed in a read-only query' % m.group(0))


_FILTER_TOKEN = re.compile(r'\(|\)|\$filter(?:-[a-z]+)?|[a-z_]\w*', re.I)
_CONDITION_START = {'where', 'having', 'on', 'prewhere', 'when'}
_CONDITION_END = {'group', 'order', 'having', 'limit', 'union', 'settings', 'then', 'window'}


def check_filter(sql):
    """Reject the two ways a query silently ignores the period: no $filter, or an OR beside it.

    Write /*no-filter*/ in the SQL to scan $log tables without $filter on purpose.
    """
    body = _SQL_TOKEN.sub(_blank_token, sql)
    if '$log' in body and '$filter' not in body and '/*no-filter*/' not in sql.replace(' ', ''):
        raise FazError('the query reads a $log table without $filter, so `period` is not applied '
                       'and it scans every stored log. Add $filter to the WHERE clause '
                       '(WHERE $filter AND ...); to scan without it on purpose, add /*no-filter*/')
    depth, tokens = 0, []
    for m in _FILTER_TOKEN.finditer(body):
        t = m.group(0).lower()
        if t in (')', 'end'):  # CASE ... END nests like parentheses
            depth -= 1
        tokens.append((t, depth))
        if t in ('(', 'case'):
            depth += 1
    for i, (t, d) in enumerate(tokens):
        if not t.startswith('$filter'):
            continue
        j = i - 1  # back to the start of this condition, staying at the same nesting level
        while j >= 0 and tokens[j][1] >= d and not (tokens[j][1] == d and tokens[j][0] in _CONDITION_START):
            j -= 1
        k = i + 1  # forward to its end
        while k < len(tokens) and tokens[k][1] >= d and not (tokens[k][1] == d and tokens[k][0] in _CONDITION_END):
            k += 1
        if any(tok == 'or' and dd == d for tok, dd in tokens[j + 1:k]):
            raise FazError('`$filter AND a OR b` reads as `($filter AND a) OR b`: rows matching b '
                           'ignore the period, and the query scans every stored log. Put the OR '
                           'in parentheses: WHERE $filter AND (a OR b)')


# Fixes for FAZ / ClickHouse errors that models keep running into, appended to the error text.
_FUNCTION_FIXES = {
    'splitpart': "split_part(s, sep, n) or splitByString(sep, ifNull(s, ''))[n]",
    'toutf8': 'nothing: strings are already UTF-8',
    'uppercase': 'upper(s)', 'toupper': 'upper(s)', 'lowercase': 'lower(s)', 'tolower': 'lower(s)',
    'from_unix_timestamp': 'from_itime(itime), or toDateTime(n) for other epoch numbers',
    'from_unixtime': 'from_itime(itime), or toDateTime(n) for other epoch numbers',
    'from_utc_time': 'from_itime(itime) (FAZ time zone) or toDateTime(itime) (UTC)',
    'findstring': 'position(s, needle)',
    'extractstring': "extract(s, 'regex(with group)')",
    'doubleorzero': 'toFloat64OrZero(s)',
    'roundquantiletiming': 'quantile(0.5)(x) or quantileExact(0.95)(x)',
    'percentileexactweighted': 'quantileExact(0.95)(x)',
}
_ERROR_HINTS = (
    (r'Aggregate function .* is found in WHERE',
     'filter on aggregates with HAVING, or in an outer query'),
    (r'is found inside another aggregate function',
     'aggregate in an inner query and aggregate its alias outside (inner count(*) AS cnt, outer sum(cnt))'),
    (r'Illegal type IPv6|types? IPv6',
     "IP columns are IPv6 values: compare and LIKE on ipstr(col), e.g. ipstr(srcip) = '10.1.2.3'"),
    (r'Illegal type String of argument of function (toHour|toDate|toStartOf|toDayOf)',
     'from_itime() returns text; use toHour(toDateTime(itime, timezone())) or toDate(itime, timezone())'),
    (r'Nested type Array\(String\) cannot be inside Nullable',
     "wrap nullable strings in ifNull(col, '') before splitting them"),
    (r'LowCardinality\(UInt8\) is not supported',
     "cast the column first: CAST(ifNull(col, '') AS String)"),
    (r'no supertype for types',
     "both sides of a comparison or ifNull() need the same type: compare a number column with a "
     "number, not ''. Numeric logid (FortiAuthenticator, FortiClient) can't be filtered in WHERE"),
    (r'Missing columns:',
     'the column does not exist in this table for this device type: list the columns with '
     'faz_columns(log, dev) or read the skill column file. FortiMail, FortiWeb and FortiADC use '
     'device_id and pri (not devid, level). An inner-query alias is only visible outside if the '
     'inner query selects it'),
    (r'Timeout exceeded',
     "the FortiAnalyzer's own query time limit: use a shorter period, put the most selective "
     'condition first and aggregate instead of returning rows'),
    (r'SQL query is forbidden',
     'the FortiAnalyzer refused the query text. A possible cause is a write keyword (delete, '
     "rename, drop, ...) inside a string literal, e.g. LIKE '%Delete%': reword it "
     "(lower(msg) LIKE '%delet%')"),
)


def sql_error_hint(error, sql):
    """A short fix for a known FAZ SQL error, or '' (appended to the error for the caller)."""
    m = re.search(r'Column `?(\w+)`? is not under aggregate function', error)
    if m:
        name = m.group(1)
        if re.search(r'\bAS\s+`?%s`?\b' % re.escape(name), sql, re.I):
            return ('\nhint: `%s` is your alias and also a real column of this table; GROUP BY, '
                    'ORDER BY and HAVING take the column. Rename the alias (e.g. %s_n)' % (name, name))
        return ('\nhint: every selected column must be aggregated or listed in GROUP BY. An alias '
                'named like a real column (e.g. ... AS itime) also causes this')
    m = re.search(r'Unknown function (\w+)', error)
    if m:
        fix = _FUNCTION_FIXES.get(m.group(1).lower())
        return '\nhint: ' + ('use ' + fix if fix else "this FortiAnalyzer's ClickHouse has no such "
                             "function; see the skill's faz-sql-reference.md")
    for pattern, hint in _ERROR_HINTS:
        if re.search(pattern, error):
            return '\nhint: ' + hint
    return ''


class FazSql:
    def __init__(self, host=None, user=None, password=None, adom=None, adom_oid=None,
                 verify=None, ca_bundle=None):
        self.host = (host or os.environ.get('FAZ_HOST') or '').rstrip('/')
        self.user = user or os.environ.get('FAZ_USER')
        self.password = password or os.environ.get('FAZ_PASSWORD')
        self.adom = adom or os.environ.get('FAZ_ADOM')  # expected name (optional)
        oid = adom_oid if adom_oid is not None else os.environ.get('FAZ_ADOM_OID')
        self.adom_oid = int(oid) if oid not in (None, '') else None
        self.session_adom = None  # name of the ADOM the session is working in
        self._adom_oids = {}      # ADOM name -> oid, filled by discovery (may be shared)
        self._relogin = False
        if not self.host or not self.user:
            raise FazError('not configured: set FAZ_HOST and FAZ_USER (and FAZ_PASSWORD) in the '
                           'environment or the env file (FAZ_ENV_FILE, else .env next to fazsql.py)')
        if verify is None:
            verify = os.environ.get('FAZ_INSECURE', '') not in ('1', 'true', 'yes')
        ca_bundle = ca_bundle or os.environ.get('FAZ_CA_BUNDLE')
        ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._cj = http.cookiejar.CookieJar()
        self._op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cj),
            urllib.request.HTTPSHandler(context=ctx))
        self._choices = None
        self._logged_in = False

    # -- context manager -------------------------------------------------
    def __enter__(self):
        self.login()
        return self

    def __exit__(self, *exc):
        self.logout()

    # -- transport ---------------------------------------------------------
    def _cookie(self, name):
        for c in self._cj:
            if c.name == name:
                return urllib.parse.unquote(c.value)
        return None

    def _http(self, path, body=None, method=None, headers=None, timeout=90):
        h = {'Content-Type': 'application/json', 'Origin': self.host,
             'Referer': self.host + '/ui/report/defs/datasets',
             'X-Requested-With': 'XMLHttpRequest'}
        h.update(headers or {})
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.host + path, data=data, headers=h, method=method)
        try:
            with self._op.open(req, timeout=timeout) as r:
                return r.status, r.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', 'replace')
        except urllib.error.URLError as e:
            raise FazError('cannot reach %s: %s' % (self.host, e.reason))
        except OSError as e:  # read timeout, connection reset mid-response
            raise FazError('request to %s failed: %s' % (self.host, e))

    def _call(self, path, body=None, method=None, timeout=90, _retry=True):
        """Authenticated request; re-logs in once if the session has expired."""
        if not self._logged_in:
            self.login()
        status, text = self._http(path, body, method,
                                  {'XSRF-TOKEN': self._cookie('HTTP_CSRF_TOKEN') or ''}, timeout)
        expired = status in (401, 403) or 'invalid login time' in text[:300]
        if expired and _retry and not self._relogin:
            self._relogin = True
            try:
                self._logged_in = False
                self.login()
            finally:
                self._relogin = False
            return self._call(path, body, method, timeout, _retry=False)
        return status, text

    # -- session -------------------------------------------------------------
    def login(self):
        if self.password is None:
            raise FazError('no password: set FAZ_PASSWORD')
        status, text = self._http('/cgi-bin/module/flatui_auth', {
            'url': '/gui/userauth', 'method': 'login',
            'params': {'username': self.user, 'secretkey': self.password}})
        if status != 200:
            raise FazError('login failed: HTTP %s' % status)
        if not (self._cookie('CURRENT_SESSION') and self._cookie('HTTP_CSRF_TOKEN')):
            # Never retry automatically: repeated bad logins can lock the account.
            raise FazError('login failed (no session cookies); check credentials: ' + text[:200])
        self._logged_in = True
        self._select_adom()

    def _proxy(self, url, method, params=None):
        """GUI proxy call; returns the result's (status, data)."""
        status, text = self._call('/cgi-bin/module/flatui_proxy',
                                  {'url': url, 'method': method, 'params': params or {}})
        try:
            r = json.loads(text)['result'][0]
        except (ValueError, KeyError, IndexError):
            raise FazError('%s %s: HTTP %s: %s' % (method, url, status, text[:200]))
        return r.get('status') or {}, r.get('data')

    def _adom_get(self):
        _, data = self._proxy('/gui/session/adom', 'get')
        return data if isinstance(data, dict) else {}

    def _adom_change(self, oid):
        st, _ = self._proxy('/gui/session/adom', 'change', {'oid': oid})
        return st.get('code') == 0, st.get('message') or st

    def _select_adom(self):
        """Put the session in the requested ADOM (FAZ_ADOM_OID, else found by FAZ_ADOM name)."""
        cur = self._adom_get()
        self.session_adom = cur.get('name')
        try:
            target = self.adom_oid
            if target is None and self.adom and self.session_adom != self.adom:
                target = self._find_adom_oid(self.adom, cur.get('oid'))
            if target is not None and target != cur.get('oid'):
                ok, msg = self._adom_change(target)
                if not ok:
                    raise FazError('cannot switch to ADOM oid %s: %s' % (target, msg))
                self.session_adom = self._adom_get().get('name')
            if self.adom and self.session_adom != self.adom:
                raise FazError('session is in ADOM %r, expected %r' % (self.session_adom, self.adom))
        except Exception:
            self.logout()  # do not leak the session we just opened
            raise

    def _find_adom_oid(self, name, current_oid):
        """Find the oid of ADOM `name` by trying the ADOM ids seen in devtable_ext."""
        if name in self._adom_oids:
            return self._adom_oids[name]
        r = self._execute('select distinct adomoid from devtable_ext', 0, LOGTYPES['traffic'],
                          PERIODS['today'], 0, '', '', 60, 0.5)
        oids = sorted({int(row[0]) for row in r['rows'] if row and row[0].lstrip('-').isdigit()})
        seen = {}
        for oid in oids:
            if oid == current_oid:
                continue
            ok, _ = self._adom_change(oid)
            if not ok:
                continue  # no access to this ADOM
            seen_name = self._adom_get().get('name')
            seen[seen_name] = oid
            self._adom_oids[seen_name] = oid
            if seen_name == name:
                return oid
        if current_oid is not None:
            self._adom_change(current_oid)  # leave the session where it started
        raise FazError('ADOM %r not found among the ADOMs this account can enter (%s); '
                       'only ADOMs with registered devices can be discovered, otherwise set '
                       'FAZ_ADOM_OID' % (name, ', '.join(sorted(map(str, seen))) or 'none'))

    def logout(self):
        """End the GUI session (frees one of the account's limited login sessions)."""
        if not self._logged_in:
            return
        try:
            self._http('/p/logout-api/', {}, method='POST',
                       headers={'XSRF-TOKEN': self._cookie('HTTP_CSRF_TOKEN') or ''}, timeout=15)
        except FazError:
            pass
        self._logged_in = False

    # -- device / log types ----------------------------------------------------
    def type_choices(self):
        """{dev-type number: {log-type id: number}} as this FAZ offers them (cached)."""
        if self._choices is None:
            status, text = self._call('/p/report/dataset/logtypechoices/?adom=%s'
                                      % urllib.parse.quote(self.session_adom or self.adom or 'root'),
                                      method='GET')
            if status != 200:
                raise FazError('logtypechoices: HTTP %s' % status)
            out = {}
            try:
                for entry in json.loads(text):
                    dev = entry['devInfo']['dev-type']
                    for c in entry['choices']:
                        out.setdefault(dev, {})[c['id']] = LOGTYPES.get(c['id'])
            except (ValueError, KeyError, TypeError):
                raise FazError('logtypechoices: unexpected response: ' + text[:200])
            self._choices = out
        return self._choices

    def _types(self, dev, log):
        dev_n = _resolve(dev, DEVTYPES, 'device type')
        log_n = _resolve(log, LOGTYPES, 'log type')
        try:
            offered = self.type_choices().get(dev_n)
        except FazError:
            offered = None  # listing unavailable: trust the static tables
        if offered is not None and log_n not in offered.values():
            names = ', '.join(sorted(offered))
            raise FazError('log type %s is not available for device type %s (available: %s)'
                           % (log, dev, names))
        return dev_n, log_n

    # -- queries -------------------------------------------------------------------
    def _start(self, sql, dev_n, log_n, period_n, last_n, start, end, timeout):
        status, text = self._call('/p/report/dataset/sql/run/', {
            'query': sql, 'devices': [], 'all-devices': True,
            'dev-type': dev_n, 'log-type': log_n, 'period-type': period_n,
            'period-last-n': last_n, 'period-start': start, 'period-end': end,
            'console-type': 'test_console'}, timeout=timeout)
        if status != 200:
            raise FazError('run: HTTP %s: %s' % (status, text[:300]))
        text = text.strip()
        if text.isdigit():
            return int(text)
        try:
            j = json.loads(text)
        except ValueError:
            raise FazError('run: unexpected response: ' + text[:300])
        raise FazError('run: ' + json.dumps(j.get('error') or j.get('extra_errors') or j)[:300])

    def _fetch(self, rid):
        status, text = self._call('/p/report/dataset/sql/fetch/?request-id=%d' % rid, method='GET')
        if status != 200:
            raise FazError('fetch: HTTP %s: %s' % (status, text[:300]))
        try:
            return json.loads(text)
        except ValueError:
            raise FazError('fetch: unexpected response: ' + text[:300])

    def cancel(self, rid):
        try:
            self._call('/p/report/dataset/sql/cancel/?request-id=%d' % rid, method='GET', timeout=15)
        except FazError:
            pass  # best effort

    def _execute(self, sql, dev_n, log_n, period_n, last_n, start, end, timeout, poll,
                 lock=None, cancelled=None):
        """Start a query and poll it to completion (no validation).

        lock: optional context manager held only around each HTTP step (not while sleeping),
        so other threads can use the session during a long query. cancelled: optional
        threading.Event; when set the query is cancelled and FazCancelled is raised.
        """
        lock = lock or contextlib.nullcontext()
        with lock:
            rid = self._start(sql, dev_n, log_n, period_n, last_n, start, end, 90)
        deadline = time.monotonic() + timeout
        lost = 0
        try:
            while True:
                if cancelled is not None and cancelled.is_set():
                    with lock:
                        self.cancel(rid)
                    raise FazCancelled('query cancelled')
                if time.monotonic() > deadline:
                    with lock:
                        self.cancel(rid)
                    raise FazError('timeout after %ds; query cancelled' % timeout)
                try:
                    with lock:
                        j = self._fetch(rid)
                except FazError as e:
                    if 'invalid request-id' in str(e) and lost < 3:
                        lost += 1  # brief gap between completion and delivery
                        time.sleep(poll)
                        continue
                    raise
                if 'error' in j:
                    error = str(j['error'])
                    raise FazError('sql error: ' + error[:400] + sql_error_hint(error, sql))
                if 'detail' in j:
                    return self._decode(j['detail'])
                time.sleep(poll)  # still running
        except KeyboardInterrupt:
            self.cancel(rid)
            raise

    def _prepare(self, sql, dev, log, period, last_n, start, end, read_only):
        """Validate and resolve a query; returns the leading arguments of _execute."""
        if read_only:
            check_read_only(sql)
            check_filter(sql)
        if log in (None, ''):
            log = infer_log_type(sql) or 'traffic'
        if str(log).strip().lower() in UNLISTED_LOGS:
            # FortiMail's $log-malware is its virus table; FortiSandbox runs its tables as event
            log = 'virus' if _resolve(dev, DEVTYPES, 'device type') == DEVTYPES['fortimail'] else 'event'
        dev_n, log_n = self._types(dev, log)
        period, last_n = normalize_period(period, last_n)
        period_n = _resolve(period, PERIODS, 'period')
        if period_n in PERIOD_NEEDS_N and last_n < 1:
            raise FazError('period %r needs last_n >= 1' % period)
        if last_n and period_n not in PERIOD_NEEDS_N:
            raise FazError("last_n only works with last-n-hours, last-n-days and last-n-weeks; for "
                           "the last %d days use period='%dd' (or period='last-n-days', last_n=%d)"
                           % (last_n, last_n, last_n))
        start, end = start.strip().lower(), end.strip().lower()
        if period_n == PERIOD_CUSTOM:
            for v in (start, end):
                if v and not (_RELATIVE.match(v) or _ABSOLUTE.match(v)):
                    raise FazError("bad custom time %r: use 'hh:mm YYYY/MM/DD' or relative "
                                   "'now', '-90m', '-24h', '-7d', '-2w'" % v)
            if not start:
                raise FazError("period 'custom' needs start")
            if not end:
                if not _RELATIVE.match(start):
                    raise FazError("period 'custom' needs end (it may only be left out when start "
                                   "is relative, such as '-24h')")
                end = 'now'
        elif start or end:
            raise FazError("start/end are only used with period 'custom'")
        return sql, dev_n, log_n, period_n, last_n, start, end

    def _probe(self, sql, args, lock=None):
        """First row of a small helper query run with the period of `args`, as a dict."""
        r = self._execute(sql, *args[1:], 60, 0.5, lock=lock)
        if not r['rows']:
            raise FazError('probe returned no row')
        return dict(zip(r['headers'], r['rows'][0]))

    def resolve_relative(self, args, lock=None):
        """Replace relative custom start/end ('now', '-24h') with times on the FAZ clock.

        FAZ reads custom times in its own time zone with minute precision, and the end is
        inclusive only up to hh:mm:00. So the start is rounded down and the end up to a whole
        minute; the window covers the asked span plus at most a minute on either side.
        """
        start, end = args[5], args[6]
        if args[3] != PERIOD_CUSTOM or not (_RELATIVE.match(start) or _RELATIVE.match(end)):
            return args
        def ago(v):
            m = _RELATIVE.match(v)
            return int(m.group(1)) * _UNIT_SECONDS[m.group(2)] if m and m.group(1) else 0
        exprs = []
        for name, v, rnd in (('s', start, 0), ('e', end, 59)):
            if _RELATIVE.match(v):
                exprs.append('toString(toStartOfMinute(toDateTime(toUnixTimestamp(now()) - %d + %d)))'
                             ' as %s' % (ago(v), rnd, name))
        row = self._probe('select ' + ', '.join(exprs),
                          args[:3] + (0, 0, '', ''), lock)  # period 'today': no custom needed
        def fmt(v):  # 'YYYY-MM-DD hh:mm:ss' -> 'hh:mm YYYY/MM/DD'
            d, t = v.split(' ')
            return '%s %s' % (t[:5], d.replace('-', '/'))
        start = fmt(row['s']) if 's' in row else start
        end = fmt(row['e']) if 'e' in row else end
        return args[:5] + (start, end)

    def window(self, args, lock=None):
        """The time range $filter covers for `args`, in the FAZ's time zone."""
        row = self._probe('select toString(toDateTime($start_time)) as s, '
                          'toString(toDateTime($end_time)) as e, timezone() as tz', args, lock)
        return {'start': row['s'], 'end': row['e'], 'tz': row['tz']}

    def query(self, sql, dev='fortigate', log=None, period='7d', last_n=0,
              start='', end='', timeout=120, poll=1.0, read_only=True, lock=None, cancelled=None):
        """Run one query and return {'headers','rows','truncated','window','adom','dev','log'}.

        dev/log accept names ('fortigate', 'dns') or numbers. When log is omitted it is taken
        from the first `$log-<type>` macro in the SQL (a bare `$log` falls back to traffic).
        period is a name from PERIODS; 'custom' needs start/end ('hh:mm YYYY/MM/DD' in the FAZ
        time zone, or relative: 'now', '-90m', '-24h', '-7d', '-2w'; end defaults to 'now'
        for a relative start), the last-n-* ones need last_n. At most ROW_CAP rows come back;
        `truncated` is True when the cap was reached. `window` is the time range $filter
        covered ({start, end, tz}), absent if it couldn't be read. lock/cancelled: see _execute.
        """
        args = self._prepare(sql, dev, log, period, last_n, start, end, read_only)
        return self.run_prepared(args, timeout, poll, lock=lock, cancelled=cancelled)

    def run_prepared(self, args, timeout, poll=1.0, lock=None, cancelled=None):
        """Run the arguments from _prepare: resolve relative times, query, add the window."""
        args = self.resolve_relative(args, lock)
        result = self._execute(*args, timeout, poll, lock=lock, cancelled=cancelled)
        result.update(adom=self.session_adom, dev=args[1], log=args[2])
        try:
            result['window'] = self.window(args, lock)
        except FazCancelled:
            raise
        except FazError:
            pass  # the rows are what matters; the window is a convenience
        return result

    def columns(self, log, dev='fortigate', period='7d'):
        """Column names of a log type, read from one real row (needs data in the period).

        Note: `*` hides ALIAS columns; confirm a "missing" column by selecting it directly.
        """
        names = {v: k for k, v in LOGTYPES.items()}
        name = names.get(log) if isinstance(log, int) else str(log).strip().lower()
        if name not in LOGTYPES and name not in UNLISTED_LOGS:
            raise FazError('unknown log type %r (known: %s)'
                           % (log, ', '.join(sorted(set(LOGTYPES) | UNLISTED_LOGS))))
        sql = ("select arrayStringConcat(JSONExtractKeys(formatRowNoNewline('JSONEachRow', *)), "
               "', ') as cols from (select * from $log-%s where $filter limit 1) t" % name)
        r = self.query(sql, dev=dev, log=name, period=period)
        if not r['rows']:
            raise FazError('no %s logs in period %r on this ADOM; try a longer period' % (name, period))
        return r['rows'][0][0].split(', ')

    @staticmethod
    def _decode(detail):
        cells = detail.get('cells') or []  # absent when the result is empty
        def cell(c):
            try:
                return urllib.parse.unquote(str(c))
            except Exception:
                return str(c)
        headers = [cell(c) for c in cells[0]] if cells else []
        rows = [[cell(c) for c in r] for r in cells[1:]]
        return {'headers': headers, 'rows': rows,
                'truncated': bool(detail.get('truncated')) or len(rows) >= ROW_CAP}


def _print(result, fmt):
    h, rows = result['headers'], result['rows']
    if fmt == 'json':
        print(json.dumps([dict(zip(h, r)) for r in rows], indent=2))
    elif fmt == 'csv':
        w = csv.writer(sys.stdout, lineterminator='\n')
        w.writerow(h)
        w.writerows(rows)
    else:
        print('\t'.join(h))
        for r in rows:
            print('\t'.join(r))
    w = result.get('window')
    note = '(%d rows%s%s%s)' % (len(rows), ', truncated at %d - add GROUP BY/filters' % ROW_CAP
                                if result['truncated'] else '',
                                ', ADOM %s' % result['adom'] if result.get('adom') else '',
                                ', %s - %s %s' % (w['start'], w['end'], w['tz']) if w else '')
    print(note, file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(description='Read-only SQL against FortiAnalyzer.')
    ap.add_argument('sql', nargs='*', help='SQL text (quote it)')
    ap.add_argument('--dev', default=None, help='device type name or number (default: fortigate)')
    ap.add_argument('--log', default=None,
                    help='log type name or number (default: from the $log-<type> macro, else traffic)')
    ap.add_argument('--period', default='7d', help='one of: ' + ', '.join(PERIODS))
    ap.add_argument('--last-n', type=int, default=0, help='N for last-n-* periods')
    ap.add_argument('--start', default='',
                    help="custom start: 'hh:mm YYYY/MM/DD' (FAZ time zone) or relative ('-24h')")
    ap.add_argument('--end', default='',
                    help="custom end: 'hh:mm YYYY/MM/DD' or 'now' / '-1h' (default 'now' for a relative start)")
    ap.add_argument('--timeout', type=int, default=120)
    ap.add_argument('--format', choices=('tsv', 'csv', 'json'), default='tsv')
    ap.add_argument('--columns', metavar='LOG', help='list the columns of a log type (needs data)')
    ap.add_argument('--list-types', action='store_true',
                    help='show the log types this FAZ offers per device type')
    ap.add_argument('--adom-oid', type=int, default=None, help='numeric ADOM id (overrides FAZ_ADOM_OID)')
    ap.add_argument('--adom', default=None, help='ADOM name to work in (overrides FAZ_ADOM)')
    ap.add_argument('--insecure', action='store_true', help='skip TLS verification (lab only)')
    a = ap.parse_args(argv)

    if not os.environ.get('FAZ_PASSWORD') and sys.stdin.isatty():
        os.environ['FAZ_PASSWORD'] = getpass.getpass('FAZ password: ')
    try:
        with FazSql(adom=a.adom, adom_oid=a.adom_oid,
                    verify=False if a.insecure else None) as faz:
            if a.list_types:
                want = _resolve(a.dev, DEVTYPES, 'device type') if a.dev else None
                for dev, logs in sorted(faz.type_choices().items()):
                    if want is not None and dev != want:
                        continue
                    print('dev-type %-3s %s' % (dev, ', '.join(
                        '%s=%s' % (k, '?' if v is None else v) for k, v in sorted(logs.items(), key=lambda kv: (kv[1] is None, kv[1] or 0)))))
                return 0
            if a.columns:
                print('\n'.join(faz.columns(a.columns, dev=a.dev or 'fortigate', period=a.period)))
                return 0
            if not a.sql:
                ap.error('give a SQL query, or --list-types / --columns')
            result = faz.query(' '.join(a.sql), dev=a.dev or 'fortigate', log=a.log, period=a.period,
                               last_n=a.last_n, start=a.start, end=a.end, timeout=a.timeout)
            _print(result, a.format)
        return 0
    except FazError as e:
        print('error: %s' % e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    sys.exit(main())
