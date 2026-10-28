#!/usr/bin/env python3
"""MCP server (stdio) exposing read-only FortiAnalyzer SQL via fazsql.FazSql.

Put the credentials in a git-ignored .env next to this script (see .env.example), then register:
  claude mcp add fortianalyzer-sql-mcp -- <path>\\.venv\\Scripts\\python.exe <path>\\fazsql_mcp.py
For several ADOMs, use one env file each: add --env FAZ_ENV_FILE=<path>\\.env.<adom>.
Optional env: FAZ_ADOM_OID (skip the ADOM id discovery), FAZ_CA_BUNDLE, FAZ_INSECURE=1 (lab only),
FAZ_IDLE_LOGOUT (seconds of inactivity before the FAZ session is closed; default 300, 0 = never).

One FAZ session is shared, logged out after the idle period (it is reopened on the next call)
and on exit. One server instance works in one FAZ and one ADOM; register it once per ADOM.

Queries run as background jobs: faz_query waits up to `wait` seconds and, if the query is still
running, returns a job_id to follow with faz_query_status / faz_query_cancel. Other tools stay
usable meanwhile. Optional env: FAZ_JOB_TIMEOUT (seconds before a job is cancelled; default 1800),
FAZ_MAX_JOBS (concurrent running jobs; default 2; further queries wait in a queue),
FAZ_MAX_QUEUED (queued jobs before new ones are rejected; default 8), FAZ_MAX_WAIT (cap on
`wait`, kept below the MCP client's request timeout; default 45).
"""
import asyncio
import atexit
import os
import threading
import time
import uuid

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

import fazsql

server = MCPServer(
    'fortianalyzer-sql-mcp',
    instructions=(
        'Read-only SQL against a FortiAnalyzer log database. Write queries in the FortiAnalyzer '
        'dataset dialect: FROM $log-<type> (e.g. $log-dns, $log-traffic) WHERE $filter ... If a '
        'skill for FortiAnalyzer dataset queries (faz-dataset) is available, read it before the '
        'first query: SKILL.md, faz-sql-reference.md and the file for the device type; read them '
        'again if your context was compacted. Use faz_query to test with a short period and a '
        'small LIMIT. faz_list_types shows which log types exist per device type; faz_columns '
        'lists the columns of a log type. Results are capped at 100 rows; when a result is '
        'truncated, follow its `note` instead of drawing conclusions from the partial rows.'))

IDLE_LOGOUT = int(os.environ.get('FAZ_IDLE_LOGOUT', '300'))
JOB_TIMEOUT = int(os.environ.get('FAZ_JOB_TIMEOUT', '1800'))
MAX_JOBS = int(os.environ.get('FAZ_MAX_JOBS', '2'))
MAX_QUEUED = int(os.environ.get('FAZ_MAX_QUEUED', '8'))
MAX_WAIT = int(os.environ.get('FAZ_MAX_WAIT', '45'))  # stay below the client's request timeout
JOB_KEEP = 900  # seconds a finished job stays retrievable

_lock = threading.RLock()  # guards the shared session; held per HTTP step, not per query
_faz = None
_last_used = 0.0
_adom_oids = {}  # name -> oid discovered so far; survives idle logouts


def _session():
    global _faz
    if _faz is None:
        try:
            faz = fazsql.FazSql()  # reads FAZ_* from the environment
        except fazsql.FazError as e:
            raise fazsql.FazError('%s. This FortiAnalyzer server is not usable until the user '
                                  'configures it: use another FortiAnalyzer server if one is '
                                  'available, and do not look for credentials yourself' % e) from e
        faz._adom_oids = _adom_oids
        faz.login()
        _faz = faz
    return _faz


def _touch():
    global _last_used
    _last_used = time.monotonic()


def _close():
    global _faz
    if _faz is not None:
        _faz.logout()
        _faz = None


def _idle_watch():
    while True:
        time.sleep(15)
        with _lock:  # waits for a running query
            if (_faz is not None and not _active_jobs()
                    and time.monotonic() - _last_used > IDLE_LOGOUT):
                _close()


if IDLE_LOGOUT > 0:
    threading.Thread(target=_idle_watch, daemon=True, name='faz-idle-logout').start()
atexit.register(_close)


class _Job:
    def __init__(self, sql):
        self.id = uuid.uuid4().hex[:8]
        self.sql = sql
        self.started = time.monotonic()
        self.finished = None
        self.state = 'queued'  # queued | running | done | error | cancelled
        self.result = None
        self.error = None
        self.cancel = threading.Event()
        self.done = threading.Event()

    def elapsed(self):
        return int((self.finished or time.monotonic()) - self.started)


_jobs = {}
_jobs_lock = threading.Lock()
_slots = threading.BoundedSemaphore(MAX_JOBS)  # one per query running on the FAZ


def _active_jobs():
    with _jobs_lock:
        return sum(1 for j in _jobs.values() if j.state in ('queued', 'running'))


def _prepare(**kwargs):
    """Validate a query before it is queued, so mistakes come back at once."""
    with _lock:
        try:
            return _session()._prepare(read_only=True, **kwargs)
        finally:
            _touch()


def _job_worker(job, args):
    try:
        while not _slots.acquire(timeout=1):  # queued: wait for a free slot
            if job.cancel.is_set():
                raise fazsql.FazCancelled('query cancelled')
        try:
            job.state = 'running'
            with _lock:
                faz = _session()
            result = faz.run_prepared(args, JOB_TIMEOUT, lock=_lock, cancelled=job.cancel)
            job.result, job.state = result, 'done'
        finally:
            _slots.release()
    except fazsql.FazCancelled:
        job.state = 'cancelled'
    except fazsql.FazError as e:
        job.error, job.state = str(e), 'error'
    except Exception as e:  # keep the job record meaningful; never lose the thread silently
        job.error, job.state = '%s: %s' % (type(e).__name__, e), 'error'
    finally:
        job.finished = time.monotonic()
        _touch()
        job.done.set()


def _submit(sql, args):
    with _jobs_lock:
        now = time.monotonic()
        for jid in [k for k, j in _jobs.items() if j.finished and now - j.finished > JOB_KEEP]:
            del _jobs[jid]
        active = sum(1 for j in _jobs.values() if j.state in ('queued', 'running'))
        if active >= MAX_JOBS + MAX_QUEUED:
            raise fazsql.FazError('%d queries are already running or queued; wait for them '
                                  '(faz_query_status) or cancel one (faz_query_cancel)' % active)
        job = _Job(sql)
        _jobs[job.id] = job
    threading.Thread(target=_job_worker, args=(job, args), daemon=True,
                     name='faz-job-' + job.id).start()
    return job


def _get_job(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is None:
        raise fazsql.FazError('unknown job_id %r (jobs expire %d min after finishing)'
                              % (job_id, JOB_KEEP // 60))
    return job


def _report(job):
    """Job outcome as a tool result: rows when done, a status stub while running."""
    if job.state == 'done':
        return dict(job.result, status='done', job_id=job.id)
    if job.state == 'error':
        raise fazsql.FazError(job.error)
    if job.state == 'cancelled':
        return {'status': 'cancelled', 'job_id': job.id}
    return {'status': job.state, 'job_id': job.id, 'elapsed_seconds': job.elapsed(),
            'hint': 'call faz_query_status(job_id) to wait for the result'
                    + (' (queued: %d queries are already running)' % MAX_JOBS
                       if job.state == 'queued' else '')}


async def _wait_report(job, wait):
    wait = min(wait, MAX_WAIT)  # return before the MCP client gives up on the request
    if wait > 0:
        await asyncio.to_thread(job.done.wait, wait)
    return _report(job)


def _run_types(dev):
    with _lock:
        try:
            choices = _session().type_choices()
        finally:
            _touch()
    want = fazsql._resolve(dev, fazsql.DEVTYPES, 'device type') if dev else None
    return {str(d): {name: num for name, num in sorted(logs.items())}
            for d, logs in sorted(choices.items()) if want is None or d == want}


def _run_columns(log, dev, period):
    with _lock:
        try:
            faz = _session()
            return {'adom': faz.session_adom, 'log': log, 'columns': faz.columns(log, dev, period)}
        finally:
            _touch()


@server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                         idempotentHint=True, openWorldHint=False))
async def faz_query(sql: str, dev: str = 'fortigate', log: str = '',
                    period: str = '7d', last_n: int = 0, start: str = '', end: str = '',
                    wait: int = 45) -> dict:
    """Run one read-only SELECT/WITH query against the FortiAnalyzer log database.

    Before your first query, read the faz-dataset skill if you have it (SKILL.md,
    faz-sql-reference.md and the file for the device type), and again after a context
    compaction. Its column names and pitfalls differ from plain SQL and ClickHouse.

    Write the query like a FortiAnalyzer dataset: FROM $log-<type> (e.g. $log-dns, $log-traffic,
    $log-attack, $log-webfilter) WHERE $filter ... $filter adds the time range of `period`; a
    query on a $log table without it is rejected. Put ORs next to it in parentheses:
    WHERE $filter AND (a OR b). Filter aggregates with HAVING, compare IPs as ipstr(srcip) =
    '10.1.2.3', and don't give an alias the name of a real column (AS total, AS itime).
    `log` is optional: it is taken from the first $log-<type> macro in the SQL (a bare $log needs
    it, default traffic). `dev` is the device type (fortigate, fortimail, fortiweb, ...); an
    invalid dev/log combination is rejected, so call faz_list_types if unsure.

    period: today, yesterday, this-week, last-week, 7d, 14d, 30d, this-month, last-month,
    this-quarter, last-quarter, this-year, '<N>h' / '<N>d' / '<N>w' (e.g. '90d', same as
    last-n-days with last_n=90), or custom (needs start; end defaults to 'now' for a relative
    start). last_n is only used with the last-n-* periods.
    All periods are in the FAZ's time zone. Whether 7d, 14d, 30d and last-n-days end now or at
    yesterday 23:59:59 has differed between queries (October 2026: 7d, 30d and last-n-days ran
    up to now, one 14d query ended yesterday), and this-week started on Monday. So don't
    describe a window from its name: every result has `window` {start, end, tz}, the range
    $filter actually covered. Read it and state it when you report numbers. For an exact span,
    use period='custom' with start/end: relative ('now', '-90m', '-24h', '-7d', '-2w') or
    absolute in FAZ time ('hh:mm YYYY/MM/DD'; '2026-10-14 11:00' and a bare date also work).
    The end is inclusive only up to hh:mm:00. Times in SQL: $flex_timescale() and from_itime() show FAZ time, but
    toString/toDate/toHour(itime) give UTC; dtime is each device's own clock, which can differ
    by hours between devices, so compare devices on itime.

    At most 100 rows are returned, whatever the SQL LIMIT says. `total_rows` is the size of the
    full result (a lower bound of 1000 when `total_rows_exact` is false). When `truncated` is
    true, the rows are only the first 100 in the query's order (arbitrary without ORDER BY):
    never count them or conclude a value is absent from them; follow the `note` in the result
    (aggregate, top N, narrower period, or page with a stable ORDER BY plus LIMIT 100 OFFSET
    100, 200, ...). Prefer GROUP BY, ORDER BY ... LIMIT and tight filters over raw rows; use a
    short period and a small LIMIT while developing a query. Only single SELECT/WITH
    statements are accepted (no CREATE/DROP/temp tables). hcache (###(...)###) works.
    Bytes: use coalesce(sentdelta,sentbyte,0) / coalesce(rcvddelta,rcvdbyte,0); sentbyte alone
    is cumulative and inflates totals.

    Long queries: the query runs as a background job and this call waits up to `wait` seconds
    (0 = return at once, at most FAZ_MAX_WAIT, default 45). If it is not finished by then, it
    returns {status: "running" or "queued", job_id, elapsed_seconds} and keeps going: follow it
    with faz_query_status(job_id) instead of submitting the query again, or stop it with
    faz_query_cancel(job_id). Tell the user a long query is in progress; a shorter period or
    tighter filter usually finishes faster. At most FAZ_MAX_JOBS queries (default 2) run at
    once; further ones wait in a queue, so run queries one after another when you can.

    FortiSandbox `malware` and `netalert`: write FROM $log-malware / $log-netalert with
    dev='fortisandbox'; leave `log` empty. Dates from toDate() and dtime come back as Unix
    epoch numbers; wrap them in toString() for readable dates.

    Errors from the FortiAnalyzer often end with a `hint:` line: apply it before retrying.
    Returns {status: "done", headers, rows, truncated, total_rows, total_rows_exact, window,
    adom, dev, log, job_id}, plus `note` when truncated; `adom` is the ADOM that was queried.
    """
    try:
        args = await asyncio.to_thread(_prepare, sql=sql, dev=dev, log=log or None, period=period,
                                       last_n=last_n, start=start, end=end)
        job = _submit(sql, args)
    except fazsql.FazError as e:  # anticipated failure: let the model read the reason
        raise ToolError(str(e)) from e
    try:
        return await _wait_report(job, wait)
    except asyncio.CancelledError:
        job.cancel.set()  # the client gave up before it saw the job_id: free the FAZ
        raise
    except fazsql.FazError as e:
        raise ToolError(str(e)) from e


@server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                         idempotentHint=True, openWorldHint=False))
async def faz_query_status(job_id: str, wait: int = 30) -> dict:
    """Check a query started by faz_query that returned status "running" or "queued".

    Waits up to `wait` seconds for it to finish (0 = check at once, at most FAZ_MAX_WAIT).
    Returns the same result as faz_query when done, {status: "running" or "queued",
    elapsed_seconds} while it runs or waits for a slot, or
    {status: "cancelled"}; a failed query raises its error. A finished job can be read again
    for 15 minutes.
    """
    try:
        return await _wait_report(_get_job(job_id), wait)
    except fazsql.FazError as e:
        raise ToolError(str(e)) from e


@server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                         idempotentHint=True, openWorldHint=False))
async def faz_query_cancel(job_id: str) -> dict:
    """Cancel a running query (frees it on the FortiAnalyzer). No effect on a finished job."""
    try:
        job = _get_job(job_id)
    except fazsql.FazError as e:
        raise ToolError(str(e)) from e
    job.cancel.set()
    await asyncio.to_thread(job.done.wait, 10)
    return {'status': job.state, 'job_id': job.id}


@server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                         idempotentHint=True, openWorldHint=False))
async def faz_columns(log: str, dev: str = 'fortigate', period: str = '7d') -> dict:
    """List the columns of a log type (e.g. dns, traffic, attack, webfilter) in the current ADOM.

    Reads one real row, so it needs at least one log of that type in `period` (try a longer
    period if it reports none). `SELECT *` hides ALIAS columns: if a column you expect is
    missing, confirm by selecting it directly in faz_query. If the faz-dataset skill is
    available, its column files also give types and meanings; use this tool for log types it
    doesn't cover (FortiProxy, ...) and to confirm. FortiSandbox: log='malware' or 'netalert'
    with dev='fortisandbox' work here too. `period` takes the same values as in faz_query.

    Returns {adom, log, columns}.
    """
    try:
        return await asyncio.to_thread(_run_columns, log, dev, period)
    except fazsql.FazError as e:
        raise ToolError(str(e)) from e


@server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                         idempotentHint=True, openWorldHint=False))
async def faz_list_types(dev: str = '') -> dict:
    """List the log types this FortiAnalyzer offers per device type, with their numbers.

    Pass dev (name such as fortigate, or number) to show a single device type; leave it empty
    for all. Keys are dev-type numbers (0 FortiGate, 3 FortiClient, 4 FortiMail, 5 FortiWeb,
    10 FortiSandbox, 15 FortiProxy, 20 FortiADC, 21 FortiFirewall, ...); values map log type
    name to number (null = not a type the API takes by itself; FortiSandbox `malware` and
    `netalert` still work as $log-malware / $log-netalert in faz_query).
    """
    try:
        return await asyncio.to_thread(_run_types, dev or None)
    except fazsql.FazError as e:
        raise ToolError(str(e)) from e


if __name__ == '__main__':
    server.run()
