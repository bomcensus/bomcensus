# bomcensus frontend

Admin console. It talks to the admin API (`/api/v1`, `api/openapi/admin.yaml`) of `bomcensus-server`, which also serves the built files.

## Running

Requires Node 26 and pnpm.

```sh
nvm use
pnpm install
BOMCENSUS_API=http://localhost:8080 pnpm dev   # http://localhost:3000, /api is forwarded to BOMCENSUS_API
pnpm typecheck
pnpm generate                                   # static build: .output/public
pnpm generate:api                               # regenerate app/api/gen from admin.yaml
```

## Layout

```
app/
  api/           API calls (index.ts) and the generated client (gen/, do not edit)
  composables/   useLoad, useMeta, useCurrentUser
  middleware/    session check
  pages/         screens
  components/    shared components
  layouts/       side menu and top bar (default), login (bare)
  types/         API types, re-exported from api/gen
  utils/         labels and formatting
  assets/css/    color and font tokens (main.css)
```

- Pages load data through `~/api` and `useLoad`, and import types from `~/types`.
- Colors and fonts come only from the tokens in `app/assets/css/main.css`.
- TypeScript is pinned to 6.x because `vue-tsc` does not support 7.x yet.
