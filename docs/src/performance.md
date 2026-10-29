# Performance

NeoZen's hot paths are benchmarked by `bench/run.py`, in the repository. It times each operation against SQLite on disk, so storage I/O is included, and reports the median and the 95th percentile.

```bash
uv run python bench/run.py            # every benchmark
uv run python bench/run.py oauth scim # only those whose name matches
```

## Baseline

Measured on 2026-10-29, NeoZen 0.9.1, on an Apple M1 (8 cores, 16 GB), macOS 14.8, Python 3.12.14, SQLAlchemy 2.0.49 with aiosqlite. Times are for one operation, in milliseconds.

| Benchmark | What one operation does | Median | p95 |
|-----------|-------------------------|-------:|----:|
| `password_hash` | Hash a password with Argon2id (`PasswordHash.recommended()`) | 54.9 | 90.6 |
| `password_verify` | Verify a password against its Argon2id hash | 54.4 | 74.5 |
| `magic_link` | Issue a magic link (store the token, send the email), then sign in with it | 4.3 | 12.3 |
| `oauth_code_flow` | Authorization request with an existing grant, then the token exchange, PKCE S256, public client | 3.4 | 5.4 |
| `scim_list` | `GET /Users` with a two-clause filter over 1,000 users, one page of 100 | 2.9 | 3.3 |
| `permission_check` | `has_permission` for a subject with five roles, the match in the last | 0.6 | 1.0 |

Argon2 dominates anything that checks a password, on purpose: its cost is what makes a stolen hash expensive to crack. A confidential OAuth client pays it too, since its secret is stored the same way, so its token exchange takes about 55 ms more than the public client's above.

Run the benchmarks on your own hardware before sizing a deployment: the numbers above only compare one NeoZen version with the next.

## Database queries

The admin console's pages and the permission check run a fixed number of queries, whatever the size of the tables: lists are filtered, sorted and paged in the database, counts are computed there, and related rows come from joins. `tests/b_integration/admin/test_admin_queries.py` checks it, by counting the statements each operation sends with small and larger data sets.
