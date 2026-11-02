# TrustShield
**Detect. Verify. Protect.** A responsive cybersecurity analysis workspace with private account login and Neon PostgreSQL persistence.

## Included
- React + TypeScript responsive security dashboard.
- Message, URL and marketplace listing heuristic analyzers.
- Private email/password registration and sign-in.
- Passwords hashed server-side with Node.js scrypt; sessions use signed, HttpOnly cookies.
- Per-account scan history, investigation titles and evidence SHA-256 metadata stored in Neon.
- Evidence files are fingerprinted in the browser and are **not uploaded**.
- Printable report and JSON export.

## 1. Prepare Neon
The three original TrustShield tables already exist in the `public` schema. In Neon Console, open SQL Editor and run the complete file `neon/schema.sql`. It creates `app_users`, adds account ownership columns and indexes to the existing tables.

## 2. Configure environment variables
In the project root, create `.env` (or add the same values in Vercel Project Settings → Environment Variables):

```env
DATABASE_URL=your-Neon-pooled-connection-string
SESSION_SECRET=a-long-random-secret-at-least-32-characters
```

Use the **pooled** Neon connection string. Keep `DATABASE_URL` and `SESSION_SECRET` server-side only. Never add a `VITE_` prefix, paste secrets into source files, or commit `.env`.

Generate a session secret with a password manager or a cryptographically secure generator. Do not reuse your Neon database password as the session secret.

## 3. Run locally
Install Node.js LTS, extract the ZIP, then in the `TrustShield` folder:

```bash
npm install
npx vercel dev
```

`vercel dev` serves the Vite app and the `/api` serverless functions together. The plain `npm run dev:vite` command starts only the frontend and will not provide the authentication/database API.

## 4. First account
Open the local URL printed by Vercel. Choose **Create account**, enter your email and a unique password of at least 12 characters. Sign in on later visits. Each account sees only its own records through user-scoped API queries.

## 5. Build

```bash
npm run build
```

For Vercel deployment, import this project/repository into Vercel and set `DATABASE_URL` and `SESSION_SECRET` in Project Settings → Environment Variables before deploying.

## Security and limitations
- Database credentials never enter browser JavaScript. All database access is through server-side API functions.
- Passwords are salted and hashed with scrypt; sessions are signed and stored in HttpOnly, SameSite cookies.
- This starter does not yet include email verification, password reset, MFA, login rate limiting, or administrator approval. Do not reuse a password from another service. If public deployment is planned, add rate limiting and email verification before treating it as a production identity system.
- The Evidence Locker stores metadata and SHA-256 fingerprints only, not the evidence file itself. It is not a certified chain-of-custody system.
- Risk scores are heuristic indicators, not proof of maliciousness or safety. External threat-intelligence integrations are not configured.
