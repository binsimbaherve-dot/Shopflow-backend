# ShopFlow Threat Model

**Author:** Herve Binsimba
**Date:** 2026-05-19
**Status:** Initial draft (design stage, pre-build)
**Methodology:** STRIDE
**Scope:** ShopFlow backend API, frontend, MySQL database, Stripe integration

---

## 1. Purpose

This document identifies security threats to the ShopFlow e-commerce platform *before*
implementation begins. It is reviewed and updated whenever the architecture changes
(new service, new external integration, new data type stored).

Each threat is mapped to a mitigation that appears as a task in the project backlog.
The goal is that by the end of Month 6, every High-rated threat below has a corresponding
implemented control and a corresponding test in one of the QA frameworks
(REST Assured, Selenium, JDBC, or BDD).

---

## 2. System Overview

ShopFlow is a small e-commerce platform built for portfolio demonstration. It supports
customer registration, browsing a product catalogue, cart management, checkout with
Stripe, order history, and an admin panel for product and order management.

### 2.1 Components

| Component         | Technology              | Hosting         | Trust level |
|-------------------|-------------------------|-----------------|-------------|
| Frontend SPA      | React                   | Render/Railway  | Untrusted (runs in user browser) |
| Backend API       | Spring Boot 3.x         | Render/Railway  | Trusted     |
| Database          | MySQL 8                 | Same VPC as API | Trusted     |
| Payment provider  | Stripe (sandbox)        | Stripe-hosted   | External, trusted via signed webhooks |
| Identity          | Self-issued JWT (HS256) | In backend      | Trusted     |

### 2.2 Data flow diagram (textual)

```
   [User Browser]
        |
        |  HTTPS
        v
   [React Frontend]  <---- untrusted: runs on user device, anything in JS is public
        |
        |  HTTPS, JWT Bearer token in Authorization header
        v
====================== TRUST BOUNDARY 1 (internet -> backend) =====================
        |
        v
   [Spring Boot API]
        |              \
        | JDBC          \  HTTPS + webhook signature
        v                v
   [MySQL]           [Stripe]
        ^                |
        |                |  HTTPS webhook (payment_intent.succeeded)
========|================|========== TRUST BOUNDARY 2 (stripe -> backend) =========
        |                |
        +----------------+
                    [Spring Boot webhook handler]
```

Two trust boundaries exist:

1. **Internet → Backend API.** Anyone in the world can send HTTP requests. We must
   authenticate, authorise, validate, and rate-limit every request.
2. **Stripe → Backend webhook endpoint.** Stripe is external. We must verify the
   `Stripe-Signature` header on every webhook so attackers cannot forge fake
   "payment succeeded" events.

### 2.3 Assets

What an attacker would want to steal, modify, or destroy:

| Asset                       | Confidentiality | Integrity | Availability |
|-----------------------------|-----------------|-----------|--------------|
| User passwords (hashed)     | High            | High      | Medium       |
| JWT signing secret          | Critical        | Critical  | High         |
| JWTs in transit / storage   | High            | High      | Medium       |
| Stripe API secret key       | Critical        | Critical  | High         |
| Stripe webhook secret       | High            | Critical  | High         |
| Order records               | Medium          | High      | High         |
| Payment records             | High            | High      | High         |
| Product catalogue           | Low             | High      | High         |
| Admin role assignments      | Medium          | Critical  | High         |
| Audit logs                  | Medium          | Critical  | High         |
| DB credentials              | Critical        | Critical  | High         |
| User PII (email, address)   | High            | Medium    | Medium       |

### 2.4 Actors

| Actor              | Trust   | Capability                                       |
|--------------------|---------|--------------------------------------------------|
| Anonymous visitor  | None    | Browse public catalogue, register, log in       |
| Authenticated customer | Low | Place orders, view own order history             |
| Admin              | High    | Manage products, view all orders, issue refunds |
| Stripe (signed)    | Medium  | Send payment event webhooks                      |
| Internal attacker  | Low–High | Anyone above, abusing their access              |
| External attacker  | None    | Tries to become any of the above                |

---

## 3. STRIDE Threat Analysis

Each threat has: ID, description, affected component, likelihood (L/M/H), impact (L/M/H),
overall rating (Low/Medium/High/Critical), and the mitigation task ID from the project
backlog. Likelihood × Impact gives the rating.

### 3.1 Spoofing (S)

| ID    | Threat | Component | Likelihood | Impact | Rating | Mitigation |
|-------|--------|-----------|------------|--------|--------|------------|
| S-01  | Attacker steals a JWT (XSS, intercepted, leaked logs) and impersonates the user | Auth | M | H | **High** | Short-lived access tokens (15 min) + refresh rotation (sec_1); HttpOnly cookies for refresh; no token in URLs; CSP headers (sec_8) |
| S-02  | Credential stuffing on `/auth/login` (reused passwords from public breaches) | Auth | H | M | **High** | Rate limiting on `/auth/*` with Bucket4j (sec_7); password complexity rules; consider HaveIBeenPwned check |
| S-03  | Attacker forges a Stripe webhook saying a payment succeeded, gets free goods | Webhook | M | H | **High** | Verify `Stripe-Signature` header on every webhook (sec_7); reject unsigned requests with 400 |
| S-04  | JWT forged with weak/leaked signing secret | Auth | L | Critical | **High** | Strong randomly generated secret, stored in env not git (sec_1, sec_3); rotate on suspicion of leak |
| S-05  | Phishing of admin credentials | Admin | M | H | **High** | Out of scope for code, but MFA on admin accounts is a future improvement |
| S-06  | "Forgot password" link replayed to take over an account | Auth | M | H | **High** | Single-use, short-expiry reset tokens; invalidate on use; rate-limit (sec_7) |

### 3.2 Tampering (T)

| ID    | Threat | Component | Likelihood | Impact | Rating | Mitigation |
|-------|--------|-----------|------------|--------|--------|------------|
| T-01  | Client modifies cart prices client-side before checkout | Cart, Order | H | H | **Critical** | Server is authoritative: re-fetch product price from DB at order creation, never trust client-supplied price |
| T-02  | JWT payload modified to change `role` from `customer` to `admin` | Auth | M | Critical | **Critical** | Signature verification on every request (sec_1); never trust JWT claims without verifying signature |
| T-03  | SQL injection via search field, login, or any parameter | API | M | Critical | **Critical** | Parameterised queries only — JPA/JPQL with bind params; SQL injection audit (sec_9) |
| T-04  | Mass assignment: `POST /api/users` with `{"role":"admin"}` sets caller as admin | API | M | Critical | **Critical** | DTOs separate from entities; `@JsonIgnore` on sensitive fields; Bean Validation (sec_6) |
| T-05  | Stored XSS via product name / description fields rendered in React | Frontend, Product | M | H | **High** | React escapes by default; never use `dangerouslySetInnerHTML`; input sanitisation server-side; CSP (sec_8) |
| T-06  | CSRF on state-changing endpoints (if cookies are used for auth) | API | L | H | **Medium** | Use Bearer tokens not cookies for auth; if cookies used, SameSite=Lax + CSRF token; CORS lockdown (sec_6) |
| T-07  | Order data modified directly in DB by attacker with stolen DB credentials | DB | L | Critical | **High** | DB credentials in env vars, not source (sec_3); least-privilege DB user; audit logs (sec_10) |

### 3.3 Repudiation (R)

| ID    | Threat | Component | Likelihood | Impact | Rating | Mitigation |
|-------|--------|-----------|------------|--------|--------|------------|
| R-01  | Customer disputes an order they placed; no proof of who placed it | Order | M | M | **Medium** | Log every order with user_id, timestamp, IP, user-agent; immutable audit table (sec_10) |
| R-02  | Admin denies issuing a refund or deleting a product | Admin | M | H | **High** | Immutable audit log of all admin actions: refunds, role changes, product deletes (sec_10) |
| R-03  | Login events not recorded; can't tell if an account was compromised | Auth | M | M | **Medium** | Log every login (success and failure) with IP and user-agent; alert on geo-anomalies (future) |
| R-04  | Webhook events from Stripe not logged; can't reconcile if dispute arises | Webhook | M | M | **Medium** | Persist raw webhook payload + verification result before processing |

### 3.4 Information Disclosure (I)

| ID    | Threat | Component | Likelihood | Impact | Rating | Mitigation |
|-------|--------|-----------|------------|--------|--------|------------|
| I-01  | IDOR: `GET /api/orders/42` returns order 42 even if caller is not the owner | Order | H | H | **Critical** | Always check ownership server-side; never trust client-supplied IDs; IDOR/BOLA tests (sec_9) |
| I-02  | API response includes sensitive fields (password hash, internal IDs, role) | API | M | H | **High** | DTOs with only required fields; never serialise entities directly; review every endpoint response |
| I-03  | Stack traces / error details leaked to client in 500 responses | API | H | M | **High** | Global exception handler returns generic error messages; full stack only in server logs |
| I-04  | Secrets (DB password, JWT secret, Stripe key) committed to git history | Repo | M | Critical | **High** | GitLeaks workflow scans every PR (sec_3); use `.env` files git-ignored; rotate any leaked secret immediately |
| I-05  | Verbose Swagger / Actuator endpoints exposed in production | API | M | M | **Medium** | Disable Spring Boot Actuator endpoints in prod; Swagger gated behind auth or disabled |
| I-06  | PII (email, address) in plaintext logs | Logging | H | M | **High** | Log redaction; never log full request bodies on auth or order endpoints; structured logging |
| I-07  | Directory listing or backup files exposed on web server | Frontend hosting | L | H | **Medium** | Host config disables directory listing; `.env` and backup files never deployed |
| I-08  | CORS misconfiguration: `Access-Control-Allow-Origin: *` with credentials | API | M | H | **High** | CORS lockdown to known origins, never wildcard in prod (sec_6) |

### 3.5 Denial of Service (D)

| ID    | Threat | Component | Likelihood | Impact | Rating | Mitigation |
|-------|--------|-----------|------------|--------|--------|------------|
| D-01  | Brute force on `/auth/login` consumes resources, locks users | Auth | H | M | **High** | Bucket4j rate limiting per IP and per username (sec_7); account lock after N failures with cool-off |
| D-02  | Large JSON request body (e.g., 100MB) crashes the JVM | API | M | H | **High** | Spring config: `spring.servlet.multipart.max-request-size`, max JSON size; reject early |
| D-03  | Expensive search query (no pagination, `LIKE '%a%'`) exhausts DB | Product | M | M | **Medium** | Mandatory pagination; index search columns; query timeout |
| D-04  | DB connection pool exhausted by long-running queries | DB | M | H | **High** | HikariCP timeout + pool size limit; query timeout at JDBC level |
| D-05  | Webhook endpoint flooded with forged requests | Webhook | M | M | **Medium** | Signature verification rejects forgeries early (sec_7); rate-limit by IP |
| D-06  | Public registration endpoint abused to create millions of accounts | Auth | M | M | **Medium** | Rate-limit `/auth/register` (sec_7); CAPTCHA on suspicion; email verification before activation |

### 3.6 Elevation of Privilege (E)

| ID    | Threat | Component | Likelihood | Impact | Rating | Mitigation |
|-------|--------|-----------|------------|--------|--------|------------|
| E-01  | Customer calls admin endpoint (`POST /api/products`, `POST /api/refunds`) | API | H | Critical | **Critical** | `@PreAuthorize("hasRole('ADMIN')")` on every admin endpoint, server-side enforced; tested per endpoint (sec_5) |
| E-02  | Customer accesses another customer's data via IDOR | API | H | H | **Critical** | Ownership check on every record access (sec_9); see I-01 |
| E-03  | Mass assignment escalates role on update | API | M | Critical | **Critical** | See T-04; role field never accepted from request body |
| E-04  | First registered user is auto-admin (forgotten dev shortcut) | Auth | M | Critical | **Critical** | No role auto-assignment in code; admins promoted explicitly via DB or admin-only endpoint |
| E-05  | JWT lacks role claim, backend defaults to admin | Auth | L | Critical | **High** | Default deny: missing role → least privilege; explicit role required for every authorised endpoint |
| E-06  | Path traversal in file upload (e.g., avatar) writes outside intended dir | API | L | H | **Medium** | If file upload is added later, validate filename; store with generated names; never use user-supplied paths |

---

## 4. Risk Summary

| Rating   | Count |
|----------|-------|
| Critical | 9     |
| High     | 20    |
| Medium   | 11    |
| Low      | 0     |

All Critical and High items must have implemented mitigations and corresponding tests
by end of Month 6. Medium items are documented and re-evaluated each month.

---

## 5. Out of Scope (Documented Assumptions)

These are deliberately *not* threat-modelled in this iteration. If any of them change,
update this document:

- Physical security of hosting infrastructure (Render/Railway responsibility).
- DDoS at the network layer (hosting provider responsibility).
- Supply-chain attacks on npm / Maven dependencies — partially mitigated by Snyk and
  Dependabot (sec_4, sec_5) but a full SBOM review is in Month 4 (sec_10).
- macOS / iOS testing scenarios (Klipboard JD says Android priority).
- Multi-factor authentication for admins (noted as future improvement).
- GDPR / POPIA compliance review (separate workstream; relevant since I'm based in South Africa).

---

## 6. Review Cadence

- **Initial review:** end of Week 0 (this document).
- **Re-review triggers:**
  - New external integration added (e.g., shipping provider).
  - New data type stored (e.g., user phone numbers for OTP).
  - Authentication mechanism changes.
  - Any Critical or High finding from a SAST, DAST, or pen test scan.
- **Scheduled review:** end of every month, alongside the `METRICS.md` update.

---

## 7. References

- Adam Shostack, *Threat Modeling: Designing for Security* (Wiley, 2014).
- OWASP Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- OWASP Top 10 (2021): https://owasp.org/Top10/
- Microsoft STRIDE: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- OWASP API Security Top 10: https://owasp.org/API-Security/editions/2023/en/0x00-header/
