# new-api Zero-Day Discovery — Findings Registry (Final)

Target: new-api (Go LLM API gateway, fork of one-api) at /workspace/new-api
Attacker model: simple registered unprivileged user (Docker + MySQL + Redis production deployment).

## PRIMARY CHAIN — Trust-Quota Overdraft: free model consumption at scale (CONFIRMED, code-verified end-to-end)

**Impact: unlimited free consumption of paid upstream models, bounded only by attacker concurrency. Wallet driven arbitrarily negative.**

Verified chain:

1. **Users can self-create `unlimited_quota` tokens.** `controller/token.go:335` — `AddToken` copies client-supplied `UnlimitedQuota` verbatim (UI exposes the checkbox; token quota is designed as a sub-limit only).
2. **Trust bypass skips ALL pre-deduction.** `service/billing_session.go:297-330` (`shouldTrust`): for synchronous relay (not tasks — `ForcePreConsume` is only set for async tasks, `relay/relay_task.go:301`), when token is unlimited (or token_quota > trustQuota) AND `relayInfo.UserQuota > 10 * QuotaPerUnit` (hardcoded $10, `common/quota.go:3-5`), `effectiveQuota = 0` — **nothing is reserved from the wallet** (`billing_session.go:191-197`).
3. **Balance check happens once, before the request.** `service/billing_session.go:365-382` (`tryWallet`): `GetUserQuota` is read at request start; K concurrent requests all read the same positive balance and all pass.
4. **No mid-stream re-check.** The streaming relay path (`relay/compatible_handler.go`, `relay/helper/stream_scanner.go`) contains no balance validation between stream start and settle.
5. **Settle is an unconditional, floorless deduction.** `BillingSession.Settle` (`billing_session.go:42-80`) → `WalletFunding.Settle(delta)` (`service/funding_source.go:57-65`) → `model.DecreaseUserQuota` → `decreaseUserQuota` (`model/user.go:1334-1340`): `UPDATE users SET quota = quota - ?` — no `WHERE quota >= ?`, no floor; the code comment (`billing_session.go:246-249`) acknowledges balances may go negative by design.
6. **No per-user concurrency limiter exists; the model rate limit is OFF by default** (`setting/rate_limit.go:21` `ModelRequestRateLimitEnabled = false`). Global API rate limit applies only to `/api` and dashboard routes, not `/v1` relay. Per-stream bounds: `STREAMING_TIMEOUT=300s` (`common/init.go:178`), `max_tokens` capped at MaxInt32/2 — effectively unbounded per stream.

**Exploitation (from a fresh account):**
1. Register (free; `QuotaForNewUser=0` default).
2. Get wallet > $10 once: top up $10.01 (or any deployment where QuotaForNewUser / check-in / gift codes exceed $10).
3. `POST /api/token/` with `{"name":"x","unlimited_quota":true,"expired_time":-1}`.
4. Fire K concurrent streaming requests (`max_tokens` maxed, expensive models: Claude Opus / o1-class if configured). Every request is "trusted" — zero reserved.
5. Each settle deducts its full actual cost unconditionally. Final balance = $10.01 − Σ(K × per-stream cost) → arbitrarily negative.
6. Free consumption ≈ K × per-stream cost. K is unbounded (no concurrency cap, no default rate limit). Per-stream cost bounded only by 300s stream + max_tokens (MaxInt32/2).

Precondition: one-time wallet > $10 (seed money). After that, consumption is free at any scale. Redis cache lag (`GetUserQuota(id,false)` reads cache, decrements are async) slightly widens the window but is not required for the exploit.

**Adversarial double-check (all verified in code):**
- `maxTokensLimit = math.MaxInt32 / 2` (`relay/helper/valid_request.go:122`) — per-stream output effectively unbounded; only the 300s streaming timeout caps it.
- The pre-consume estimate is prompt-based (`relay/helper/price.go:165` `QuotaToPreConsume`), so a small prompt + huge `max_tokens` passes the `userQuota - preConsumedQuota >= 0` gate trivially while actual settle cost is output-driven.
- `ValidateUserToken` skips the token-quota check for unlimited tokens (token quota is a sub-limit by design).
- Wallet-credit enumeration (every `IncreaseUserQuota`/`creditTopUpQuota` call site): admin edit, payment settlement (signed), redemption (CAS), check-in (unique-index, default off), invite bonus (default 0), legitimate refunds of pre-consumed quota. **No free balance-inflation primitive exists** — in a strict default deployment the $10.01 seed must come from one real top-up (or any deployment with QuotaForNewUser/check-in/trial codes above $10, where a fresh registration suffices with zero payment).
- No mid-stream balance check exists anywhere in the streaming path (grep of `compatible_handler.go`/`stream_scanner.go` for quota reads: none).

## SECONDARY CHAINS

### Chain 2 — `tryRealtimeFetch` user-triggered terminal flip skips settlement/refund (Gemini/Vertex video tasks)
- `relay/relay_task.go:474-531`: user's own `GET /v1/videos/:task_id` polls upstream directly and persists terminal status via `task.UpdateWithStatus(snap.Status)` **without** `settleTaskBillingOnComplete` / `RefundTaskQuota`. `UpdateWithStatus` (`model/task.go:508-514`) permits ANY transition incl. FAILURE→SUCCESS.
- Poller only settles when it wins the terminal CAS (`service/task_polling.go:557-581`); terminal tasks are never re-polled (`model/task.go:344-353`).
- **Refund+delivery exploit:** poller sees a poll-level error body (`plugins/tasks/google/plugin.js:211` maps ANY `body.error.message` — incl. a 429 rate-limit on the poll GET itself — to `FAILURE`) → marks FAILED + full refund (`task_polling.go:539-549,578-580`). The upstream operation completes anyway; user's fetch flips FAILURE→SUCCESS and stores the video (`relay_task.go:524-527`); `GET /v1/videos/:id/content` serves it. Net: full refund kept + video delivered. Attacker can induce poll 429s by bursting submissions on the channel key.
- Also: user fetch flipping to SUCCESS before the poller skips usage-based settlement (undercharge); flipping to FAILURE skips refund (overcharge). `TaskTimeoutMinutes` default 1440.
- Precondition: Gemini or Vertex video channel configured.

### Chain 3 — Kling/Vidu `metadata` overrides outbound billing multipliers
- `plugins/tasks/kling/plugin.js:234-246` and `plugins/tasks/vidu/plugin.js:220-230`: `Object.assign(defaults, metadata)` lets the client override ANY outbound field (`duration`, `model`, `resolution`) while billing facts are computed pre-override (`kling` `extractUsage`→`outboundDuration` reads `req.duration` only, line 160-167/268-275; `vidu` `outboundDuration` line 83-87).
- `{"duration":1,"metadata":{"duration":10}}` → billed 1s, generated 10s. `metadata.model_name` override (kling) bills cheap model rates while upstream generates with the expensive one.
- Host validation (`relay/channel/task/jsplugin/adaptor.go:1177-1206`) checks each field independently (each ≤3600) — passes.
- Corrected at settlement ONLY if upstream reports actual usage (kling `final_unit_deduction`; absent → cheated estimate stands; vidu only overlays `credits`).
- Precondition: Kling/Vidu channel; magnitude bounded by upstream's own caps (≤10-15s) — a bounded undercharge (5-10×), not unlimited.

### Chain 4 — Midjourney `IN_PAINT`/`CUSTOM_ZOOM` unconditionally free (standard MJ channels)
- `relay/mjproxy_handler.go:504-506`: `consumeQuota = false` for INPAINT/CUSTOM_ZOOM regardless of upstream flavor. On standard `midjourney-proxy` upstreams the change-submit is a self-contained job (mask in body) — one paid `imagine` unlocks unlimited free inpaint/custom-zoom image generations (billed to channel owner's fast hours, $0 to user). Reachable via `POST /mj/submit/change` (`action=INPAINT`) and plus-protocol `/mj/submit/action` (`MJ::JOB::Inpaint::...`).

## CONFIRMED STANDALONE FINDINGS

| # | Finding | Location | Severity |
|---|---|---|---|
| F1 | `GET /mj/image/:id` (+`/:mode/mj/image/:id`) unauthenticated: route registered before `Use(TokenAuth())`; `GetByOnlyMJId` has no user binding; upstream error body echoed verbatim | `router/relay-router.go:196-197`, `relay/mjproxy_handler.go:29-98` | High (unauth cross-tenant read; MjId enumeration) |
| F2 | Realtime (WSS) double billing: per-event charges (`PreWssConsumeQuota`→`PostConsumeQuota`, `service/quota.go:149`) AND full-session settle (`PostWssConsumeQuota`→`SettleBilling`, `quota.go:230`) → ≈2× overcharge; invisible in logs (log records only Q). `relayInfo.UsePrice` guard is dead code (never assigned) so price-based realtime models get ratio-37.5 fallback per-event charges | `relay/channel/openai/relay_realtime.go:136-166,226-241`, `service/quota.go:88-155,157-232` | High (anti-user overcharge) |
| F3 | WSS per-event check-then-deduct TOCTOU: `PreWssConsumeQuota` reads balance then deducts non-atomically; concurrent sessions overdraw wallet/token (floors absent in `DecreaseTokenQuota`/`DecreaseUserQuota`) | `service/quota.go:92-152`, `model/user.go:1317-1340`, `model/token.go` | Medium |
| F4 | Remix billing multipliers silently discarded: `ResolveOriginTask` sets `info.PriceData.OtherRatios`, then `ModelPriceHelperPerCall` rebuilds PriceData from scratch, dropping them (`info.PriceData` is a value field) — sora remix billed flat per-call base instead of ×seconds | `relay/relay_task.go:113-139,264-269`, `relay/helper/price.go:187-253`, `plugins/tasks/sora/plugin.js:117-123` | Medium (under-billing) |
| F5 | MIME part-header injection via raw upload filename in `/v1/images/edits` (`"` + CRLF injects headers into upstream multipart) | `relay/channel/openai/adaptor.go:521,550` | Medium |
| F6 | GitHub `legacy_id` login migration takeover: `Extra["legacy_id"]` = mutable/recyclable GitHub username; login matches victim row and issues session for victim; migration failure still logs in | `oauth/github.go:152-160`, `controller/oauth.go:308-326` | High **conditional on legacy string `github_id` rows** (migrated one-api DBs) |
| F7 | Public perf-metrics endpoints leak all group names + live load/health (default-public; not usable-group-filtered unlike GetPricing) | `controller/perf_metrics.go:38-81`, `middleware/header_nav.go:17-21` | Low-Med |
| F8 | Playground `/pg/chat/completions` bypasses `ModelRequestRateLimit` + token model/IP restrictions (billing still enforced) | `router/relay-router.go:62-68` | Low-Med |
| F9 | Gemini `-nothinking` re-pricing is dead code: `PriceData` computed before the handler rewrites `OriginModelName` to `<model>-nothinking`; billed at base-model price, log claims nothinking name | `controller/relay.go:158`, `relay/gemini_handler.go:73-85`, `service/text_quota.go:233-246` | Medium |
| F10 | WSS billing mixes two models in one formula (completion/audio-completion ratios looked up by mapped upstream name, model ratio by client name) | `relay/websocket.go:44`, `service/quota.go:157-183` | Medium |
| F11 | Per-price settlement branch lacks non-positive clamp: negative ModelPrice/special ratios (no sign validation in `UpdateModelPriceByJSONString`) flow through as user credits | `service/text_quota.go:368-376`, `common/quota_math.go:86-100`, `model/option.go:578-599` | Medium (admin misconfig) |
| F12 | Upstream usage never sign-validated (`ValidUsage` only checks non-zero): negative completion_tokens can zero a bill (requires compromised upstream) | `service/usage_helpr.go:31-33`, `service/text_quota.go:378-382` | Low |
| F13 | `TaskBulkUpdateByID` marks tasks FAILURE without refund (channel-lookup-failure and null-id bulk paths) — violates its own doc warning | `service/task_polling.go:171-179,246-250,387-391` | Low-Med |
| F14 | PATs (`users.access_token`) survive password changes and session revocation — persistence primitive for any token-theft bug | `middleware/auth.go:168-179`, `model/user.go:1165-1179` | Medium |
| F15 | Public uptime-kuma fetcher: no SSRF validation, follows redirects, 2×20 upstream request amplification per anonymous hit | `controller/uptime_kuma.go:93-141` | Low-Med |
| F16 | MJ duplicate `mj_id` rows never refunded (poller map collapses duplicates); error-code tasks with non-empty result tracked but unbilled; `RelayMidjourneyNotify` dead-but-dangerous if revived (no auth/ownership) | `controller/midjourney.go:56`, `relay/mjproxy_handler.go:583-611,100-141` | Low-Med |
| F17 | Email verification codes: 24-bit entropy, no attempt counter (rate-limit only); LinuxDO `redirect_uri` from client-controlled Host; passkey RPID/origin auto-derived from Host when unconfigured; OAuth login-intent state not browser-bound (login CSRF) | `common/verification.go:26-33`, `oauth/linuxdo.go:58-62`, `service/passkey/service.go:76-123`, `controller/oauth.go:47-92` | Low-Med |
| F18 | OAuth bind check-then-act race, no unique index on provider-id columns; 30s refresh-token replay window; WeChat bridge fully trusted without signature | `controller/oauth.go:243-284`, `service/auth_session.go:232-241`, `controller/wechat.go:23-52` | Low |
| F19 | Admin can flip used redemption code back to enabled (double redemption); checkin award bypasses wallet ceiling + `rand.Intn` panic on MaxQuota<MinQuota | `controller/redemption.go:182-184`, `model/checkin.go:72-74,104-107` | Low (admin-only) |
| F20 | `new-api`-format polling responses skip `extractUsageOnComplete` (completion usage never applied); immediate-failure tasks charged in full; crash window between CAS and settlement permanently skips settle/refund; unbounded `io.ReadAll` in tryRealtimeFetch | `service/task_polling.go:469-479`, `controller/relay.go:727-741`, `relay/relay_task.go:501` | Low-Med |

## Cleared areas (verified end-to-end by agents + self)

- **Auth/session core**: role/identity always server-side; token-type confusion blocked; session tokens (HS256 purpose-derived keys, random default secret); revocation via version fences; 2FA flow (single-use auth-flow tokens, auth_version pinning); password reset (UUID token, single-use); setup endpoint re-run blocked; root undeletable.
- **Mass assignment**: AddToken/UpdateToken sanitized field-by-field with ownership + quota bounds; UpdateSelf allowlisted (username/display/password + old-password check); role pinned on all self-service paths.
- **Redemption codes**: transaction + lockForUpdate + CAS `UPDATE ... WHERE status=enabled`; wallet ceiling clamp; no double-credit.
- **Payments**: epay MD5 signature over signed params (money pinned server-side at order creation); Stripe/Creem/Waffo webhooks signature-verified, row-locked idempotent status transitions, provider guards. Gaps: no paid-amount reconciliation (S1/S2/S6-class), Creem test-mode empty-secret bypass is dead code.
- **SQL injection**: every user input parameterized/whitelisted (all 47 `.Order()` sites, LIKE sanitization with escape, whitelist sort columns).
- **SSRF core**: protected fetch client with dial-time DNS re-validation; URL content-part fetching guarded; task artifacts HMAC capability (constant-time); video proxy validates per redirect hop.
- **Frontend XSS**: all user-controlled sinks are React text or DOMPurify; only root-set options hit raw HTML; auth redirect sanitized.
- **IDOR**: token/task/log/topup/mj/subscription queries all scope by session user id; keys masked; task ids 32-char random.
- **Pricing consistency**: ability lookup and pricing use the same raw client model name (no trim/case divergence); missing ratio fails closed-expensive (37.5× fallback, request rejected unless user opts in); group ratio default 1, never 0; cache arithmetic clamped non-negative; all quota math saturated via common/quota_math.go.
- **Token cache**: mutation fences; sk-key-channelid pinning admin-gated (middleware/auth.go:519).

## Exploitability ranking (production impact)

1. **Trust-quota overdraft** — free consumption at scale on ANY channel/model (needs one-time >$10 wallet).
2. **tryRealtimeFetch flip** — free videos + refunds on Gemini/Vertex channels.
3. **MJ IN_PAINT free actions** — free image derivations on standard MJ channels.
4. **Kling/Vidu metadata override** — 5-10× underbilling on those channels.
5. **/mj/image/:id unauth** — cross-tenant image disclosure.
6. **GitHub legacy_id** — full account takeover on migrated one-api DBs.

## Blocked / exhausted approach families

SQL injection (parameterized everywhere), payment callback forgery (signed), redemption races (CAS), frontend XSS (sanitized), IDOR (scoped), session/JWT flaws (sound), setup re-run (guarded), SSRF (guarded client), token mass-assignment (sanitized), RCE via exec/template (no sinks — only xdg-open/rundll32/open in OpenBrowser for desktop builds).
