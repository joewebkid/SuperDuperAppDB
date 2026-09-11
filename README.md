# HyperHLE app compatibility database

A community-run compatibility database for [HyperHLE](https://github.com/j92580498-max/touchHLE)
(a community fork of the touchHLE iPhone OS emulator), modelled on the
original [appdb.touchhle.org](https://appdb.touchhle.org/).

Anyone can submit a compatibility report for an app they've tested after
signing in with GitHub. The site requests only the public GitHub profile,
places ordinary submissions in a moderation queue, aggregates approved
reports per app/version and can pre-fill the form from either an uploaded log
or the Super Duper Android client.

## Stack

- **FastAPI** + **Jinja2** (server-rendered HTML, no SPA)
- **SQLite / PostgreSQL** via SQLAlchemy 2.x
- Plain CSS, no build step

## Run locally

```bash
cd appdb
python -m venv .venv
source .venv/bin/activate
pip install -e .
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Then open <http://localhost:8000/>. The database is auto-created and seeded
with a handful of example apps the first time the server starts.

The SQLite file lives at `appdb/appdb.sqlite3` in development. Production can
use PostgreSQL through `DATABASE_URL`. New uploaded screenshots are stored in
the database alongside their report, which keeps them durable on free web
hosts with an ephemeral filesystem. Legacy files under `appdb/uploads/` (or
`/data/uploads/`) remain readable.

## Layout

```
appdb/
├── pyproject.toml         # dependencies + package metadata
├── README.md
└── app/
    ├── main.py            # FastAPI routes
    ├── db.py              # SQLAlchemy models, engine, init_db
    ├── seed.py            # demo data
    ├── log_parser.py      # HyperHLE / touchHLE log → form fields
    ├── templates/         # Jinja2 templates
    │   ├── base.html
    │   ├── index.html         # Apps list + per-rating stats
    │   ├── app_detail.html    # Per-app: versions + reports table
    │   ├── submit_report.html # Form to add a compatibility report
    │   └── about.html
    └── static/
        └── style.css
```

## Routes

| Method | Path | Description |
| --- | --- | --- |
| GET | `/` | Apps list + stats, optional `?q=` search |
| GET | `/apps/{id}` | App detail page (versions + reports) |
| GET | `/submit` | Compatibility report form |
| POST | `/submit` | Create a new report (and optionally a new app) |
| POST | `/submit/parse-log` | Parse uploaded HyperHLE log → re-render the form pre-filled |
| GET | `/about` | Rating scale and house rules |
| GET | `/screenshots/{report_id}` | Database-backed screenshot with the report's visibility rules |
| GET | `/uploads/{filename}` | Static — serves uploaded screenshots |
| GET | `/healthz` | Liveness check |
| POST | `/api/patch-submissions` | Strict anonymous Android patch handoff |
| GET | `/auth/github/login` | Start GitHub OAuth with state + PKCE |
| GET | `/auth/github/callback` | Complete GitHub OAuth |
| POST | `/auth/logout` | End the signed session (CSRF protected) |

## Deploying

### Self-hosted VPS and achievements

`compose.vps.yaml` runs the application and a private PostgreSQL 16 instance.
Only the application port is bound to localhost; `nginx.superduper.conf`
publishes it through the host Nginx. Keep the real `.env` on the server with
mode `0600` and never commit it. The same database stores compatibility
reports, OAuth users, moderated achievement catalogs and pending achievement
drafts.

The Android achievement client uses `GET /v1/catalog` with ETag caching,
`POST /v1/submissions` for bounded anonymous drafts and
`GET /v1/submissions/{sha256}` for public moderation status. An authenticated
administrator publishes or rejects drafts from `/admin`. Remote definitions
remain exact-revision, data-only rules and cannot execute code or write guest
memory.

The repository root contains `render.yaml` for a free Render web service with
a generated session secret and production-safe defaults. It expects a durable
external PostgreSQL connection in `DATABASE_URL`; no Render disk is required.
During Blueprint creation Render asks for the database URL, GitHub client ID,
GitHub client secret and final callback URL. Free Render web services can sleep
when idle, so the first request after a quiet period may be slower.

### GitHub OAuth and report submission

Create a GitHub OAuth App with:

- Homepage URL: the public HTTPS origin of this AppDB;
- Authorization callback URL:
  `https://<appdb-host>/auth/github/callback`.

Configure the server using the variables documented in `.env.example`.
`GITHUB_OAUTH_CLIENT_SECRET` and `SESSION_SECRET` are server-only secrets and
must never be added to an APK, a URL or source control. Production refuses to
start without a stable session secret, marks the session cookie Secure and
does not seed demo reports. Configure `TRUSTED_PROXY_HOSTS` for the actual
TLS-terminating proxy rather than trusting arbitrary forwarded headers.

The authorization flow uses a one-time state, a ten-minute deadline and PKCE
S256. The return target is restricted to a local path. Report, log upload,
logout and moderation forms are CSRF protected. Ordinary users are limited to
ten reports per hour by default; edge-level request limiting is still required
for a public deployment.

Build Android with the public AppDB origin (or an exact `/submit` URL):

```powershell
gradle :app:assembleDebug `
  -PCOMPATIBILITY_REPORT_URL=https://<appdb-host>
```

From the in-game report dialog the app opens AppDB with game/version/device/
rating/notes pre-filled. These values survive the GitHub login redirect. The
user reviews the form and submits it; a captured screenshot is exported only
after this explicit action and must still be selected by the user. When the
build property is empty, the existing pre-filled GitHub Issue path remains as
a fallback.

### Patch submission gateway

Set `PATCH_SUBMISSION_GITHUB_TOKEN` to a GitHub App installation token or a
fine-grained token limited to **Issues: write** on `SuperDuperPatches`. The
Android app never receives this secret. Optional settings are
`PATCH_SUBMISSION_REPOSITORY`, `PATCH_SUBMISSION_RATE_SALT`, and
`PATCH_SUBMISSION_MAX_PER_HOUR`.

Build Android with
`-PPATCH_SUBMISSION_URL=https://<host>/api/patch-submissions`. The gateway
validates exact IPA identity, deduplicates identical manifests, rate-limits
anonymous clients, and creates a `gateway-submission` issue. Repository
Actions then creates the draft PR. Production hosting must also apply an
edge-level rate limit; application limits alone are not a DDoS boundary.

## Notes

- HyperHLE is a community fork of touchHLE; this database is **not**
  affiliated with upstream touchHLE.
- Reports are attributable to the GitHub account that submitted them. A login
  is not evidence that a compatibility claim is correct; non-admin reports
  remain private/pending until moderation.
