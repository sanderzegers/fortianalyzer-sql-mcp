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
FAZ_MAX_JOBS (concurrent running jobs; default 2).
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
        'skill for FortiAnalyzer dataset queries (faz-dataset) is available, use it to write the '
        'SQL and use faz_query to test it with a short period and a small LIMIT. faz_list_types '
        'shows which log types exist per device type; faz_columns lists the columns of a log type. '
        'Results are capped at 100 rows.'))

IDLE_LOGOUT = int(os.environ.get('FAZ_IDLE_LOGOUT', '300'))
JOB_TIMEOUT = int(os.environ.get('FAZ_JOB_TIMEOUT', '1800'))
MAX_JOBS = int(os.environ.get('FAZ_MAX_JOBS', '2'))
JOB_KEEP = 900  # seconds a finished job stays retrievable

_lock = threading.RLock()  # guards the shared session; held per HTTP step, not per query
_faz = None
_last_used = 0.0
_adom_oids = {}  # name -> oid discovered so far; survives idle logouts


def _session():
    global _faz
    if _faz is None:
        faz = fazsql.FazSql()  # reads FAZ_* from the environment
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
            if (_faz is not None and not _running_jobs()
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
        self.state = 'running'  # running | done | error | cancelled
        self.result = None
        self.error = None
        self.cancel = threading.Event()
        self.done = threading.Event()

    def elapsed(self):
        return int((self.finished or time.monotonic()) - self.started)


_jobs = {}
_jobs_lock = threading.Lock()


def _running_jobs():
    with _jobs_lock:
        return sum(1 for j in _jobs.values() if j.state == 'running')


def _job_worker(job, kwargs):
    try:
        with _lock:
            faz = _session()
            args = faz._prepare(read_only=True, **kwargs)
        result = faz._execute(*args, JOB_TIMEOUT, 1.0, lock=_lock, cancelled=job.cancel)
        result.update(adom=faz.session_adom, dev=args[1], log=args[2])
        job.result, job.state = result, 'done'
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


def _submit(sql, **kwargs):
    with _jobs_lock:
        now = time.monotonic()
        for jid in [k for k, j in _jobs.items() if j.finished and now - j.finished > JOB_KEEP]:
            del _jobs[jid]
        running = sum(1 for j in _jobs.values() if j.state == 'running')
        if running >= MAX_JOBS:
            raise fazsql.FazError('%d queries are already running; wait for them (faz_query_status) '
                                  'or cancel one (faz_query_cancel)' % running)
        job = _Job(sql)
        _jobs[job.id] = job
    threading.Thread(target=_job_worker, args=(job, dict(sql=sql, **kwargs)), daemon=True,
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
    return {'status': 'running', 'job_id': job.id, 'elapsed_seconds': job.elapsed(),
            'hint': 'call faz_query_status(job_id) to wait for the result'}


async def _wait_report(job, wait):
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
                    wait: int = 60) -> dict:
    """Run one read-only SELECT/WITH query against the FortiAnalyzer log database.

    Write the query like a FortiAnalyzer dataset: FROM $log-<type> (e.g. $log-dns, $log-traffic,
    $log-attack, $log-webfilter) WHERE $filter ... $filter adds the time range of `period`.
    `log` is optional: it is taken from the first $log-<type> macro in the SQL (a bare $log needs
    it, default traffic). `dev` is the device type (fortigate, fortiproxy, fortiweb, ...); an
    invalid dev/log combination is rejected, so call faz_list_types if unsure.

    period: today, yesterday, this-week, last-week, 7d, 14d, 30d, this-month, last-month,
    this-quarter, last-quarter, this-year, custom (needs start and end as 'hh:mm YYYY/MM/DD'),
    or last-n-hours / last-n-days / last-n-weeks (needs last_n >= 1).

    At most 100 rows are returned (`truncated` is true when the cap is hit), whatever the SQL
    LIMIT says. Prefer GROUP BY, ORDER BY ... LIMIT and tight filters over raw rows; use a
    short period and a small LIMIT while developing a query. Only single SELECT/WITH
    statements are accepted (no CREATE/DROP/temp tables). hcache (###(...)###) works.
    Bytes: use coalesce(sentdelta,sentbyte,0) / coalesce(rcvddelta,rcvdbyte,0); sentbyte alone
    is cumulative and inflates totals.

    Long queries: the query runs as a background job and this call waits up to `wait` seconds
    (0 = return at once). If it is not finished by then, it returns {status: "running", job_id,
    elapsed_seconds} and keeps running: follow it with faz_query_status(job_id) instead of
    submitting the query again, or stop it with faz_query_cancel(job_id). Tell the user a
    long query is in progress; a shorter period or tighter filter usually finishes faster.
    At most FAZ_MAX_JOBS queries (default 2) run at once; a further one is rejected until one
    finishes.

    Log types this tool doesn't list by name, such as FortiSandbox `malware` and `netalert`:
    pass a log type it accepts for that device (dev='fortisandbox', log='event') and keep
    FROM $log-malware in the SQL; the macro decides the table. Dates from toDate() and dtime
    come back as Unix epoch numbers; wrap them in toString() for readable dates.

    Returns {status: "done", headers, rows, truncated, adom, dev, log, job_id}; `adom` is the
    ADOM that was queried.
    """
    try:
        job = _submit(sql, dev=dev, log=log or None, period=period, last_n=last_n,
                      start=start, end=end)
        return await _wait_report(job, wait)
    except fazsql.FazError as e:  # anticipated failure: let the model read the reason
        raise ToolError(str(e)) from e


@server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                         idempotentHint=True, openWorldHint=False))
async def faz_query_status(job_id: str, wait: int = 30) -> dict:
    """Check a query started by faz_query that returned status "running".

    Waits up to `wait` seconds for it to finish (0 = check at once). Returns the same result as
    faz_query when done, {status: "running", elapsed_seconds} while it runs, or
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
    missing, confirm by selecting it directly in faz_query. Use this for log types that have no
    column reference (FortiMail, FortiWeb, FortiProxy, ...).

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
    for all. Keys are dev-type numbers (0 FortiGate, 3 FortiClient, 5 FortiWeb, 15 FortiProxy,
    20 FortiADC, 21 FortiFirewall, ...); values map log type name to number (null = unknown).
    """
    try:
        return await asyncio.to_thread(_run_types, dev or None)
    except fazsql.FazError as e:
        raise ToolError(str(e)) from e


if __name__ == '__main__':
    server.run()
