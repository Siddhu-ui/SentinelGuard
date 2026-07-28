# SentinelGuard API

All endpoints except `/health` and authentication require `Authorization: Bearer <JWT>`.

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/auth/register` | Create account and receive token |
| POST | `/auth/login` | Authenticate |
| GET | `/auth/me` | Current profile |
| POST | `/scans` | Multipart upload and static scan (`file`) |
| GET | `/scans?q=` | Search owned scan history |
| GET/DELETE | `/scans/{id}` | Retrieve/delete an owned scan |
| GET | `/scans/{id}/report.pdf` | Download report |
| GET | `/dashboard` | Summary cards and recent scans |

See the running API's `/docs` for request schemas and interactive testing.
