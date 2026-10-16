# fortianalyzer-sql-mcp

An [MCP](https://modelcontextprotocol.io) server that lets Claude run SQL against the log database of a
**FortiAnalyzer 7.6**, using the same dataset query dialect you use under *Reports > Datasets*
(`$log-<type>`, `$filter`, hcache `###(...)###`, ...). A small command-line client is included.

It works through the FortiAnalyzer GUI's dataset *Test* endpoints over HTTPS, so there is nothing to
install on the FortiAnalyzer and no SSH access is needed.

> Not affiliated with or endorsed by Fortinet. The GUI endpoints it uses are not part of the documented
> `/jsonrpc` API and can change between firmware releases.

## Features

- `faz_query`: run one query and get `{headers, rows, truncated, total_rows, window, adom, dev, log}` back.
  `window` is the time range the query covered, in the FortiAnalyzer's time zone. `total_rows` is the
  size of the full result; a truncated result also carries a `note` on what to do next
- `faz_query_status` / `faz_query_cancel`: follow or stop a long-running query. `faz_query` runs
  queries as background jobs and waits up to `wait` seconds (default 60). If the query is still running
  it returns `{status: "running", job_id}` instead of blocking, and the other tools stay usable
- `faz_columns`: list the columns of a log type (read from one real log row)
- `faz_list_types`: list which log types exist per device type on your FortiAnalyzer
- Device and log types by **name** (`fortigate`, `dns`, ...) or number, checked against what your FortiAnalyzer offers
- The log type is taken from the `$log-<type>` macro in the query, so you normally do not pass it
- Work in a specific **ADOM** by name
- Session handling: logs in once, logs out after inactivity and on exit, logs in again if the session expires
- Meant to be used with the [faz-dataset skill](https://github.com/sanderzegers/fortianalyzer-dataset-skill), which knows how to write correct queries in this dialect (see [Using it](#using-it))

## Requirements

- Python 3.10 or newer
- A FortiAnalyzer 7.6 reachable over HTTPS
- A FortiAnalyzer account with **Read-Write** permission for **Reports** and **Run Reports**. All other
  permissions can be set to **None**. A dedicated account is recommended.

## Install

```bash
git clone https://github.com/sanderzegers/fortianalyzer-sql-mcp.git
cd fortianalyzer-sql-mcp
python -m venv .venv
.venv/bin/pip install -r requirements.txt        # Windows: .venv\Scripts\pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in the connection details (the file is git-ignored):

```
FAZ_HOST=https://faz.example.com
FAZ_USER=svc-claude
FAZ_PASSWORD=...
FAZ_ADOM=root
```

Register it with Claude Code (use the full paths to the venv's Python and to `fazsql_mcp.py`):

```bash
claude mcp add fortianalyzer-sql-mcp -- /path/to/fortianalyzer-sql-mcp/.venv/bin/python /path/to/fortianalyzer-sql-mcp/fazsql_mcp.py
```

On Windows, use `.venv\Scripts\python.exe` as the command. Restart Claude Code and check the server with `/mcp`.

**Claude Desktop** has no `claude mcp add`. Instead, add the server to `claude_desktop_config.json`
(*Settings > Developer > Edit Config*; on Windows `%APPDATA%\Claude\`, on macOS
`~/Library/Application Support/Claude/`) and restart Claude Desktop:

```json
{
  "mcpServers": {
    "fortianalyzer-sql-mcp": {
      "command": "C:\\path\\to\\fortianalyzer-sql-mcp\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\fortianalyzer-sql-mcp\\fazsql_mcp.py"]
    }
  }
}
```

Use the full paths (on macOS/Linux: `.venv/bin/python`). The connection settings are read from the `.env`
file next to `fazsql.py`, so there is no need to put the password in this file. To use a different env
file, add `"env": {"FAZ_ENV_FILE": "/path/to/.env.lab"}` to the entry.

One server instance works in one FortiAnalyzer and one ADOM. To use several, register it several times
under different names (for example `fortianalyzer-sql-mcp-prod` and `fortianalyzer-sql-mcp-lab`), each with
its own env file: `--env FAZ_ENV_FILE=/path/to/.env.lab`.

## Configuration

Settings are read from environment variables, and from the `.env` file next to `fazsql.py` (or the file
named by `FAZ_ENV_FILE`). Variables set in the real environment take precedence over the file.

| Variable | Description |
|---|---|
| `FAZ_HOST` | Base URL, for example `https://faz.example.com` (required) |
| `FAZ_USER` | Account name (required) |
| `FAZ_PASSWORD` | Password. The command-line client asks for it if unset |
| `FAZ_ADOM` | ADOM to work in, by name. Default: the account's default ADOM (usually `root`) |
| `FAZ_ADOM_OID` | Numeric ADOM id. Optional shortcut that skips the ADOM lookup |
| `FAZ_CA_BUNDLE` | PEM file with the CA that signed the FortiAnalyzer certificate |
| `FAZ_INSECURE` | `1` disables TLS verification (self-signed lab certificates) |
| `FAZ_IDLE_LOGOUT` | Seconds of inactivity before the session is closed. Default `300`, `0` = never |
| `FAZ_JOB_TIMEOUT` | Seconds before a running query is cancelled. Default `1800` |
| `FAZ_MAX_JOBS` | Queries allowed to run at the same time. Default `2` |

TLS verification is on by default.

### ADOMs

Queries run in the ADOM of the login session. Setting `FAZ_ADOM` makes the tool switch to that ADOM at
login, and it fails with an error rather than querying a different ADOM.

## Using it

**Install the [faz-dataset skill](https://github.com/sanderzegers/fortianalyzer-dataset-skill) as well.**
This server runs queries; it does not teach Claude how to write them. FortiAnalyzer's dataset dialect has
many quirks (the `$log-<type>` and `$filter` macros, hcache `###(...)###`, which `${...}` macros expand,
the right byte and session counters, column names per log type), and without that knowledge Claude
frequently writes queries that fail. The skill supplies exactly that, and the server then lets Claude test the query against your FortiAnalyzer before it hands it to you, so the result is a query that is known to run on your system.

The skill also works without this server. It then only produces query text for you to paste into
*Reports > Datasets*, with no connection to a FortiAnalyzer. The server can be used without the skill,
but expect more failed or wrong queries.

With both installed, ask in plain language, for example *"Which hosts made the most DNS requests in the
last 7 days, and what did the top one look up?"*. Claude writes the query with the skill and runs it with
`faz_query`. The tool arguments are:

| Argument | Description |
|---|---|
| `sql` | The query. Use `$log-<type>` as the table and `$filter` in `WHERE` |
| `dev` | Device type: `fortigate` (default), `fortiproxy`, `fortiweb`, `fortimail`, ... |
| `log` | Log type: `traffic`, `dns`, `attack`, `webfilter`, `event`, ... Optional, taken from the `$log-<type>` macro |
| `period` | `today`, `yesterday`, `7d` (default), `14d`, `30d`, `this-week`, `last-week`, `this-month`, `last-month`, `this-quarter`, `last-quarter`, `this-year`, `last-n-hours` / `last-n-days` / `last-n-weeks` (with `last_n`), or `custom` (with `start` and `end`) |
| `start`, `end` | For `custom`: `hh:mm YYYY/MM/DD` in the FortiAnalyzer's time zone, or relative to its clock: `now`, `-90m`, `-24h`, `-7d`, `-2w`. With a relative `start`, `end` defaults to `now` |

### Time periods

The periods are FortiAnalyzer's own report periods, in the FortiAnalyzer's time zone. Some of them stop
before the current day or hour:

| Period | Covers |
|---|---|
| `today`, `this-week`, `this-month`, ... | From the start of the day, week, ... up to now. Weeks start on Sunday |
| `7d`, `14d`, `30d`, `last-n-days` | Whole days up to yesterday 23:59:59: **today is not included** |
| `last-n-weeks`, `last-week` | Whole weeks (Sunday to Saturday) before the current week |
| `last-n-hours` | Whole hours up to the end of the last full hour |
| `custom` | `start` to `end`, to the minute. An absolute `end` is included only up to `hh:mm:00` |

For "the last 24 hours" up to now, use `period='custom', start='-24h'`. The tool turns relative times into
FortiAnalyzer clock times, rounding the start down and the end up to the minute. Each result includes the
`window` that was covered, for example
`{"start": "2026-10-14 17:02:00", "end": "2026-10-15 17:03:00", "tz": "Europe/Amsterdam"}`.

Example query:

```sql
select ipstr(srcip) as requester, count(*) as requests
from $log-dns
where $filter and srcip is not null
group by requester
order by requests desc
limit 10
```

## Command-line client

`fazsql.py` uses the same code and the same environment variables:

```bash
python fazsql.py --period 7d 'select ipstr(srcip) as requester, count(*) as n from $log-dns where $filter group by requester order by n desc limit 5'
python fazsql.py --list-types --dev fortigate
python fazsql.py --columns dns
python fazsql.py --format csv --period today 'select ...'
python fazsql.py --period custom --start=-24h 'select ...'   # relative times need --start=
```

Use `--adom NAME`, `--adom-oid N`, `--insecure`, `--format tsv|csv|json` and `--timeout SECONDS` as needed.

## Notes

- **Server-side limits.** The FortiAnalyzer SQL dialect only allows read queries and rejects write or
  unsafe statements itself. The tool additionally refuses anything but a single `SELECT` / `WITH` before
  sending it.
- **Row cap.** The backend returns at most 100 rows per query, whatever the SQL `LIMIT` says, and
  counts the full result up to 1000 rows (`total_rows`, with `total_rows_exact: false` beyond that).
  `truncated` is true only when rows were left out. Aggregate with `GROUP BY`, take a top N with
  `ORDER BY ... LIMIT`, or page with a stable `ORDER BY` plus `LIMIT 100 OFFSET 100`, `200`, ...
- **Concurrency.** At most `FAZ_MAX_JOBS` queries (default 2) run at once per server instance; a further
  one is rejected until one finishes. Long queries continue in the background (`faz_query_status`).
- **Log types without a name in the tool.** FortiSandbox `malware` and `netalert` aren't in the tool's
  log-type list. Pass `dev='fortisandbox', log='event'` and write `FROM $log-malware` in the SQL: the
  macro decides which table is read.
- **Dates.** `toDate()` and `dtime` come back as Unix epoch numbers; wrap them in `toString()`.
- **Time zones.** `$flex_timescale()` and `from_itime()` show FortiAnalyzer time, but `toString(itime)`,
  `toDate(itime)` and `toHour(itime)` give UTC. `dtime` is each device's own clock, which can be hours
  apart between devices.
- **Passwords.** The `.env` file holds the password in plain text: keep it git-ignored and readable only
  by you. Avoid `claude mcp add --env FAZ_PASSWORD=...`, which stores it in your Claude configuration
  instead. Use a dedicated account with minimal rights.

## Troubleshooting

| Message | Meaning |
|---|---|
| `ADOM '...' not found among the ADOMs this account can enter` | The ADOM name is wrong, has no registered devices, or the account has no access. Set `FAZ_ADOM_OID` |
| `log type ... is not available for device type ...` | That device type has no such log type. Check `faz_list_types` |
| Query returns 0 rows | Check the period and the ADOM. `$filter` limits the query to the selected period and ADOM |
| `sql error: ... Missing columns` | The column does not exist for that log type. Check `faz_columns` |
| `SQL query is forbidden.` | The FortiAnalyzer's own SQL filter rejected the statement (for example `version()`) |

## License

GPL-2.0. See [LICENSE](LICENSE).
