# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WIREX (исторически BYPASS, GitHub-репо ещё называется bypass) — VPN key management service. Users authenticate via email OTP, select a server, and receive VLESS keys/QR codes for Xray-based VPN access. The admin panel manages users and has a built-in chat system.

## Architecture

- **Backend**: Flask app (`site/app.py`) running on port 8080. Manages Xray configs on multiple remote servers via SSH, handles email verification, user CRUD, subscription file generation, and admin chat.
- **Frontend**: Single-page app (`site/index.html`) using Tailwind CSS (CDN), Space Grotesk/Inter fonts, Material Symbols icons. All UI logic is vanilla JS in a `<script>` block at the bottom of the HTML file. No build step.
- **Deployment**: `setup.sh` provisions a Linux server — installs deps, creates a virtualenv, configures systemd service (`vpn-site`). The app runs directly as root.
- **Multi-server**: The Flask backend manages Xray configs across 4 VPN servers (Amsterdam local + USA/Finland/France remote via SSH). Remote server operations use `subprocess.run(["ssh", ...])`.

## Running Locally

```bash
cd site
pip install flask qrcode[pil]
python app.py  # starts on port 8080
```

Note: Most API endpoints (`/api/create`, `/api/delete`, server stats) require SSH access to remote VPN servers and will fail locally without that connectivity.

## Key Data Flows

- **Auth**: Email → 6-digit OTP code (via SMTP to mail.ru) → session token stored in localStorage
- **Key creation**: POST `/api/create` with server + username + token → adds UUID to Xray config on target server → generates VLESS URL + subscription file + QR code
- **Subscriptions**: Base64-encoded VLESS URLs served as plain text from `/var/www/sub/<username>`
- **Admin**: Password-protected endpoints for user listing (`/api/users`), deletion (`/api/delete`), and chat (`/api/chat/*`)

## Data Storage

All data is JSON files on disk (no database):
- `/opt/vpn-site/users.json` — user records
- `/opt/vpn-site/verification_codes.json` — pending OTP codes
- `/opt/vpn-site/sessions.json` — active session tokens (email-bound, 30-day TTL)
- `/opt/vpn-site/chats.json` — admin/user chat messages
- `/opt/vpn-site/secrets.json` — admin password, SMTP credentials (chmod 600, not in repo)

## Auth Flow

1. User submits email → `/api/send-code` → 6-digit OTP emailed (rate-limited: 60s per email)
2. User submits OTP → `/api/verify-code` → server generates token, stores in `sessions.json` bound to email
3. Frontend saves token in `localStorage`, sends it on every request
4. `/api/verify-session` validates the token against `sessions.json` on page load
5. `/api/create` requires a valid session token (no more shared invite token)

## Frontend API Communication

The frontend uses a hardcoded `API_URL` constant. The `vercel.json` in `site/` rewrites `/api/*` requests to the backend server. All authenticated endpoints take the session token in the JSON body under `token`.

## Language

The project UI and comments are in Russian.
