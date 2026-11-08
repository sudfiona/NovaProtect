# CDNfly deployment for NovaProtect

`cdnfly-edge-policy.json` is a declarative rule map for the CDNfly console. It is intentionally not
presented as an official CDNfly import payload because CDNfly installations can expose different
console labels and API schemas.

The site is static. There is no session, no login and no upload endpoint, so every edge decision here
is only about two things: a challenge page must never replace a real page or asset, and caching must
follow what the origin sends.

## Apply the rules

1. Create the `page-html` rule at the highest priority for `nova.fbi.plus`.
2. Match the exact paths listed in the JSON file (`/`, `/download`, `/client-updates`, `/sdk`,
   `/privacy`, `/404.html`). Only `GET` and `HEAD` reach the origin.
3. Set edge cache and browser cache to bypass. Disable JavaScript, CC and bot challenges for this rule.
4. Create `release-feed` for `/data/` with cache set to respect-origin: the feed changes only on
   deploy and carries a short max-age.
5. Create `site-assets` for `/css/`, `/js/`, `/assets/` and `/favicon.ico`, challenges off,
   cache respect-origin.
6. Keep the fallback rule below all of them, and never rewrite an unknown path to a challenge page:
   unknown paths must reach the origin so its own 404 document is returned.
7. Purge the full site cache, including HTML. A partial purge can leave an old response cached under
   a path that now serves different files.

`X-NovaProtect-Client` is only a diagnostic/routing hint. Do not use it as an authentication or
security allow-list signal.

## What no longer exists

Removed with the backend, and deliberately absent from the policy:

| Gone | Why it is gone |
| --- | --- |
| `/admin`, `/admin/login`, `/logout` | there is no admin |
| `/install`, `/install.php` | there is no install wizard to lock |
| `/api/admin/release/*` | no upload transport |
| `/api/releases/current`, `/download` binary mirror | the client updates from GitHub directly |
| `/health` | static files do not need a health endpoint; `deploy/health-check.sh` checks the real pages |

Because none of these paths exist, a request for one now lands on the 404 document. That is the
correct outcome: the preflight asserts a 404 rather than trying to distinguish "locked" from
"missing".

## Verify the edge

```bash
bash deploy/cdnfly-check.sh https://nova.fbi.plus
```

The script fails the run if any page or asset returns HTTP 444, if a CDNfly guard body
(`/_guard/auto.js`, "human verification", "javascript challenge") reaches the client, or if a path
that must not exist fails to return 404.
