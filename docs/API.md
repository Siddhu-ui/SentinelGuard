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
| POST | `/encryption/encrypt` | Encrypt multipart `file` with `password` and `confirm_password` |
| POST | `/encryption/decrypt` | Decrypt multipart `.sguard` `file` with `password` |
| GET | `/encryption/history` | List the authenticated user's encryption/decryption history |
| GET | `/encryption/{id}/download` | Download an owner-scoped protected output |

Encryption endpoints never persist passwords or AES keys. Invalid passwords, modified ciphertext, and malformed authentication metadata all return the same safe decryption failure message.

See the running API's `/docs` for request schemas and interactive testing.
