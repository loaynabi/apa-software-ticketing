# APA Software Ticketing

A browser-based internal IT ticketing system served by a Cloudflare Worker. It includes a ticket dashboard and queue, priority-based service-level deadlines, overdue and due-soon tracking, assignment and status workflows, file attachments, live ticket chat, push notifications, reporting, and role-based access.

## Privacy and deployment

This repository contains application source code only. It does not include production tickets, employee records, user credentials, Cloudflare account identifiers, or deployment secrets. Do not add those items to Git or share them publicly.

The application is not a hosted public demo. Deploy it to an account you control and provide accounts to authorized users only. Ticket data, user records, and attachments are managed by the configured Cloudflare services.

## Requirements

- Python 3.9 or later (the deployment script uses only the standard library)
- A Cloudflare account with Workers, Workers KV, and Durable Objects enabled
- A Cloudflare API token with permission to edit Workers Scripts and Workers KV

## Provision the first admin

The first deployment needs at least one admin account. Create a private `private-data/team.csv` file with exactly these CSV headers and one row per authorized user:

```csv
name,email,role
```

Use company-domain email addresses and one of the roles `admin`, `executive`, or `user`; include at least one admin. Generate user records and random one-time passwords:

```powershell
python seed_users.py --team-csv private-data/team.csv
```

The script creates `private-data/users.json` and `private-data/initial-credentials.txt`. Both paths are Git-ignored. Distribute the initial credentials securely, require recipients to change their passwords at first sign-in, then securely delete the credentials file. Do not email these passwords or add the private files to Git.

## Deploy

1. Create a Cloudflare API token with the permissions above and save it in a local text file, for example `cf.token`.
2. Save your Cloudflare account ID in a separate local text file, for example `account.txt`.
3. From this directory, build and inspect the upload without making network calls:

   ```powershell
   python deploy.py --token-file cf.token --account-file account.txt --seed private-data/users.json --dry-run
   ```

4. When the dry run lists only the expected Worker modules and `src/index.html`, deploy:

   ```powershell
   python deploy.py --token-file cf.token --account-file account.txt --seed private-data/users.json
   ```

The script creates or reuses the `apa-software-tickets` KV namespace, generates a random session secret, and deploys the Worker with live chat support. It stores deployment metadata in `deploy_config.json` and the session secret in `.session_secret`; both are ignored by Git. Keep the session secret safe and back it up securely. Losing it invalidates existing sessions.

For later account additions, use the in-app admin user-management screen or generate a new private seed file and deploy it with `--merge`. Existing accounts are not replaced by a merge.

After deployment, the script prints the `workers.dev` URL. Configure access to that URL according to your organization's policies; do not treat a public URL as an invitation to create public user accounts.

## Repository layout

- `src/index.html` — ticketing application interface
- `worker/` — Worker API, authentication, ticket routes, notifications, and live chat
- `deploy.py` — builds and deploys the Worker
- `seed_users.py` — creates private user records and cryptographically random initial passwords

## Development

Run the deployment script's dry run after changing the frontend or Worker modules to verify the complete upload bundle. The dry run does not contact Cloudflare and does not require real credentials.
