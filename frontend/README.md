# MuleGuard frontend

The investigation interface: a single-page React application served by nginx,
talking to the FastAPI backend over `/api/v1`.

```
npm install
cp .env.example .env     # optional; the defaults work against a local backend
npm run dev              # http://localhost:5173, proxying /api to :8000
```

Everything below is either a decision that is easy to get wrong or a thing
that will bite somebody at 2am. The ordinary parts are in the code.

## What the interface is careful about

This is a fraud-detection tool, which means almost every number on screen can
be read as an accusation. A handful of rules run through the whole codebase:

**A score is a priority, not a probability.** The investigative priority score
ranks accounts for analyst attention. It is not a likelihood of guilt and does
not authorise any action. `SCORE_SEMANTICS` in `src/lib/constants.ts` is the
one sentence that says so, and it is rendered wherever a score appears out of
context. The backend publishes machine-readable guard rails
(`/model/limitations`) stating whether the score may be called a probability or
called calibrated; model monitoring renders them as a yes/no list so an analyst
writing a case note can check the sentence they are about to write.

**Risk colour is not a traffic light.** LOW is slate, not green, because a low
score means "not prioritised", not "cleared" — the detector only finds
typologies it knows about. Rendering LOW in green would tell an analyst the
opposite of what the score means. Colour is also never the only channel: every
badge carries its text label, so the interface reads correctly in greyscale and
for anyone who cannot distinguish the hues.

**"Not assessed" is not a low score.** An account nothing has analysed shows
"Not assessed", and on the network canvas it is drawn hollow. Collapsing the
two would turn an absence of evidence into evidence of innocence.

**An identity is not an inference.** Complaint correlations come in five tiers.
Tiers 1–2 are identities — the complaint named a reference that exists — and
carry no confidence value; the UI prints "identity" where a number would go,
because 1.000 implies a measurement nobody made. Tiers 3–5 are inferences with
a confidence and a review state, and until a human accepts one it is a lead.
The same distinction drives the network canvas: a solid edge is a recorded
transfer, a dashed edge is something the platform derived.

**A truncated result establishes nothing.** Every graph traversal is bounded
and clamps silently. When a limit is hit, the canvas says so in words, because
at that point "no path found" has not been demonstrated — and that is exactly
the sentence somebody is tempted to write into a referral.

**A path is a shape, not a tracing.** Money is fungible. That a chain of
transfers exists is an investigative lead; that the same funds travelled it is
a claim the data cannot support. Per-currency totals are kept apart rather than
summed, because there is no exchange rate to combine them with.

## How it is put together

```
src/
  app/          providers, router, query client, error boundary
  components/
    common/     29 primitives: inputs, table, modal, badges, pager
    charts/     recharts wrappers, each with a text summary for screen readers
    tables/     one table per domain object
    layout/     shell, navigation, route guards, environment banner
  features/     one directory per area, each with its own *Api.ts
  hooks/        10 hooks; filter and pagination state lives in the URL
  lib/          api client, formatters, permissions, query keys, tokens
  types/        the API contract, mirrored by hand
```

**The types mirror the endpoints, not the schemas.** Every endpoint module in
`backend/app/api/v1/endpoints/` declares its own Pydantic response models
inline; none of them import from `backend/app/schemas/`. The endpoint is what
answers the request, so the endpoint is the contract, and `src/types/` mirrors
those models. Two consequences worth knowing:

- **Pagination is flat.** `items` sits alongside `page`, `page_size`, `total`,
  `total_pages`, `sort_by` and `sort_order` at the top level. There is no
  `meta` envelope and no `has_next`; `pageInfo()` in `src/types/common.ts`
  extracts the fields and `Pagination` derives "is there a next page" from
  `page < total_pages`.
- **Enums arrive as plain strings.** The response models type them as `str`,
  so a value a build does not recognise is humanised and shown rather than
  dropped. Nothing disappears from a list because the backend added a state.

**Permissions come from the server.** `/auth/me` returns a map of capability
booleans resolved from the user's role and from whatever role overrides the
deployment has configured. `src/lib/permissions.ts` reads that map rather than
re-deriving permissions from the role, because a deployment that widened
`CASE_CLOSE_ROLES` would otherwise have an interface disagreeing with its own
backend. None of it is a security control: every endpoint re-resolves the real
permission on each request.

Permission gating has two modes, and the choice matters. `RoleGate` with an
`action` renders a denial naming the roles that *can* do the thing — right for
a whole page, because an analyst who cannot open the audit trail is better
served by being told who can. `RoleGate` with `silent` renders nothing — right
for one button in a toolbar, where an explanation per missing control would be
unusable.

**Filter state lives in the URL.** A filtered queue is a link a colleague can
open; this matters most on the network view, where a screenshot otherwise
travels without the limits that produced it.

**Sorting is server-side.** Sorting the current page would order 25 rows out of
40,000 and look like it ordered everything.

## Running the checks

```
npm run typecheck    # tsc --noEmit, strict
npm run lint
npm run test         # vitest
npm run build        # typecheck, then vite build
npm run preview      # serve the built bundle on :4173
```

`npm run build` runs `tsc` first on purpose: a type error should fail the
build rather than ship a bundle that crashes in a browser.

## Deployment

`docker compose up --build` from the repository root builds this image and
serves it on `${FRONTEND_PORT:-8080}`, with nginx proxying `/api` to the
backend container. The `VITE_` variables are **build args**, not runtime
environment: Vite inlines them into the bundle, so changing one means
rebuilding the image.

Three of them are safety flags — `VITE_SHOW_SYNTHETIC_BANNER`,
`VITE_SHOW_SCORE_DISCLAIMER`, `VITE_SHOW_LIMITATIONS` — and all three default
to **on** when unset. A deployment that forgot to configure them should
over-warn: a spurious banner is mildly annoying, a missing one means somebody
may act on generated output as though it described a real account.

`nginx.conf` carries a strict CSP. Two relaxations are deliberate and both are
commented there: `'unsafe-inline'` for styles, because Recharts and Cytoscape
set inline styles on the elements they draw and neither offers a nonce hook;
and `data:`/`blob:` image sources, for Cytoscape's PNG export and the inlined
SVG logo.

## Things that are not here

**`package-lock.json` is not committed.** Generating it needs network access to
the npm registry, which the environment this was written in did not have. Run
`npm install` once and commit the lockfile it produces — the Dockerfile prefers
`npm ci` when a lockfile exists and falls back to `npm install` when it does
not, so the image builds either way, but only `npm ci` gives reproducible
builds.

**There is no runtime config endpoint.** The `VITE_` values are baked in at
build time. For an internal tool rebuilt from compose that is the simpler
trade; a deployment that needs to retarget the API without rebuilding would
want a small `/config.json` fetched at startup instead.

**Cytoscape is loaded on demand.** It is the largest dependency by a wide
margin and most users never open the network view. `useCytoscape` imports it
dynamically, and if the import fails the failure is reported — the trail and
path searches do not depend on it and keep working.
