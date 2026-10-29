---
marp: true
title: NeoZen, in six slides
author: Abilian SAS
size: 16:9
paginate: false
style: |
  @import url("https://fonts.googleapis.com/css2?family=Lato:wght@400;700;900&family=JetBrains+Mono:wght@400;600&display=swap");

  :root {
    --ink: #1a2350;
    --indigo: #3f51b5;
    --accent: #c98a1b;
    --paper: #f1efe8;
    --card: #faf8f2;
    --muted: #4a5070;
  }

  section {
    font-family: "Lato", "Helvetica Neue", sans-serif;
    background: var(--paper);
    color: var(--ink);
    padding: 64px 80px;
    font-size: 24px;
    justify-content: center;
  }

  h1 { font-size: 46px; font-weight: 900; margin: 0 0 28px; color: var(--ink); }
  h1 em { font-style: normal; color: var(--indigo); }
  code, pre { font-family: "JetBrains Mono", monospace; }

  .kicker {
    font-size: 15px; font-weight: 700; letter-spacing: 0.12em;
    text-transform: uppercase; color: var(--accent); margin-bottom: 8px;
  }

  .grid { display: grid; gap: 22px; }
  .grid.three { grid-template-columns: repeat(3, 1fr); }
  .grid.two { grid-template-columns: repeat(2, 1fr); }

  .card {
    background: var(--card); border-radius: 10px; padding: 20px 24px;
    box-shadow: 0 1px 3px rgba(26, 35, 80, 0.12);
  }
  .card h3 { margin: 0 0 8px; font-size: 25px; color: var(--indigo); }
  .card p { margin: 0; font-size: 19px; line-height: 1.4; color: var(--muted); }

  .term {
    background: #10163a; color: #e6e8f2; border-radius: 10px;
    padding: 22px 26px; font-family: "JetBrains Mono", monospace;
    font-size: 18px; line-height: 1.6;
  }
  .term span { display: block; white-space: pre; }
  .term .gap { height: 1em; }
  .term .c { color: #8c93b8; }
  .term b { color: var(--accent); font-weight: 400; }

  ul.ticks { list-style: none; padding: 0; margin: 0; }
  ul.ticks li { margin: 0 0 12px; padding-left: 30px; position: relative; font-size: 22px; }
  ul.ticks li::before { content: "✓"; position: absolute; left: 0; color: var(--indigo); font-weight: 900; }

  footer { font-size: 14px; color: var(--muted); left: 80px; bottom: 28px; }

  /* The title slide. */
  section.title { background: var(--ink); color: #f1efe8; justify-content: center; }
  section.title footer { color: #b8bcd6; }
  section.title .brand { font-size: 64px; font-weight: 900; letter-spacing: 0.02em; margin: 0; }
  section.title .brand span { color: var(--accent); }
  section.title .tagline { color: #b8bcd6; font-size: 20px; margin: 0 0 30px; }
  section.title h1 { color: var(--accent); font-size: 50px; line-height: 1.12; }
  section.title p { font-size: 21px; line-height: 1.5; }
  section.title .split { display: grid; grid-template-columns: 1.05fr 1fr; gap: 50px; align-items: center; }
---

<!-- _class: title -->
<!-- _footer: "Open source, Apache 2.0 · neozen.abilian.com · Made by Abilian" -->

<div class="split">
<div>
<p class="brand">Neo<span>Zen</span></p>
<p class="tagline">AuthN + AuthZ</p>
<h1>Sign-in and permissions for Python apps.</h1>
<p>NeoZen handles authentication and authorization: as a library inside your app, or as an identity provider in front of all of them.</p>
</div>

<div class="term">
<span class="c"># a library, in your app</span>
<span><b>$</b> uv add "neozen[flask]"</span>
<span class="gap"></span>
<span class="c"># or a service, in front of your apps</span>
<span><b>$</b> docker compose up -d</span>
<span class="gap"></span>
<span class="c"># the same code, either way</span>
<span><b>$</b> neozen serve</span>
</div>

</div>

---

<div class="kicker">What it does</div>

# Everything after <em>"who are you?"</em>

<div class="grid three">
<div class="card"><h3>Sign in</h3><p>Passwords, magic links, passkeys, TOTP and email codes. Google and GitHub sign-in.</p></div>
<div class="card"><h3>Sessions</h3><p>Hashed tokens with a sliding expiry, revoked one at a time or all at once.</p></div>
<div class="card"><h3>Permissions</h3><p>Roles, permissions and policies. Groups, and invitations by email.</p></div>
<div class="card"><h3>Single sign-on</h3><p>An OAuth 2.1 server and an OpenID Connect provider for your other apps.</p></div>
<div class="card"><h3>Provisioning</h3><p>SCIM 2.0 for users and groups. LDAP and Active Directory as a user store.</p></div>
<div class="card"><h3>Administration</h3><p>A web console for users, roles, sessions and the audit log. CSV import and export.</p></div>
</div>

---

<div class="kicker">As a library</div>

# It fits <em>your</em> app, not the reverse

<div class="grid three">
<div class="card"><h3>Your framework</h3><p>Adapters for Flask, Litestar and Starlette. The core has no web framework in it, so anything else can call it.</p></div>
<div class="card"><h3>Your database</h3><p>SQLAlchemy, Peewee, Tortoise ORM or plain SQL, behind one repository protocol.</p></div>
<div class="card"><h3>Your User model</h3><p>NeoZen depends on protocols, not base classes: keep the model you have.</p></div>
</div>

<p style="margin-top: 34px; font-size: 22px; color: var(--muted);">Take only what you need: one sign-in factor and sessions, or the whole identity provider.</p>

---

<div class="kicker">As a service</div>

# Or run it <em>on its own</em>

<div class="grid two">
<div>
<ul class="ticks">
<li>An admin console, ready on first boot</li>
<li>OpenID Connect and SCIM for your other apps</li>
<li>PostgreSQL, its schema created on first start</li>
<li>Health and readiness checks for your monitoring</li>
<li>Docker Compose, or a Helm chart for Kubernetes</li>
</ul>
</div>

<div class="term">
<span><b>$</b> cd deploy/docker</span>
<span><b>$</b> docker compose up -d</span>
<span class="gap"></span>
<span class="c"># the first admin's password</span>
<span><b>$</b> docker compose logs neozen \</span>
<span>    | grep BOOTSTRAP -A 6</span>
<span class="gap"></span>
<span class="c"># then open the console</span>
<span><b>$</b> open http://localhost:8000/login</span>
</div>

</div>

---

<div class="kicker">Security</div>

# Secure <em>by default</em>

<div class="grid two">
<div class="card"><h3>Out of the box</h3><p>Argon2id password hashing. Timing-safe comparisons. Session tokens stored hashed, and rotated at sign-in. PKCE, and refresh tokens that detect replay.</p></div>
<div class="card"><h3>One setting each</h3><p>Rate limiting on sign-in and registration. Account lockout after failed attempts. An audit log of security events.</p></div>
</div>

<p style="margin-top: 34px; font-size: 22px; color: var(--muted);">Tested by more than 1,600 tests, type-checked by mypy, ty and pyrefly.</p>

---

<div class="kicker">Get started</div>

# Five minutes to your <em>first sign-in</em>

<div class="grid two">
<div class="card"><h3>Developer Quickstart</h3><p>A Litestar app with registration, sign-in and sessions.<br><br><code>uv add neozen</code></p></div>
<div class="card"><h3>Self-Hosted Quickstart</h3><p>NeoZen as an identity provider, with Docker Compose.<br><br><code>docker compose up -d</code></p></div>
</div>

<p style="margin-top: 34px; font-size: 22px;"><strong>neozen.abilian.com</strong> · Apache 2.0, no paid tier · 0.9, the first public release, is coming.</p>
