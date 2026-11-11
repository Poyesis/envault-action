# Envault secrets for GitHub Actions

Loads the secrets of an [Envault](https://envault.poyesis.fr) environment into a GitHub Actions job. The job signs in
with its own GitHub OIDC token: no Envault password or token is stored in GitHub.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # lets the job request an OIDC token
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: Poyesis/envault-action@v1
        with:
          project-id: a83e276a-…   # envault projects list (a platform's id for projects with platforms)
          environment: prod
      - run: ./deploy.sh          # sees $DATABASE_URL etc.; values show as *** in the logs
```

Only some keys, as step outputs instead of variables for every later step:

```yaml
      - uses: Poyesis/envault-action@v1
        id: vault
        with:
          project-id: a83e276a-…
          environment: prod
          keys: DATABASE_URL, JWT_SECRET   # a missing key fails the step
          export-to-env: false
          set-outputs: true
      - run: ./migrate.sh
        env:
          DATABASE_URL: ${{ steps.vault.outputs.DATABASE_URL }}
```

Before the first run, grant the workflow access in Envault (see [Server side](#server-side)).

| Input | Default | |
| --- | --- | --- |
| `project-id`, `environment` | required | |
| `api-url` | `https://api.envault.poyesis.fr` | Change it only for a self-hosted Envault. |
| `audience` | `envault` | OIDC audience; must match the Envault workload issuer config. |
| `keys` | all | Comma/newline-separated filter. |
| `export-to-env` | `true` | Append to `$GITHUB_ENV` for later steps. |
| `mask` | `true` | `::add-mask::` every value (and each line of multi-line values). |
| `set-outputs` | `false` | Also expose values as `steps.<id>.outputs.<KEY>`. |

Output `keys`: comma-separated names that were loaded (never values).

With `export-to-env` (the default) every later step of the job sees the secrets, including third-party actions.
To give them to one command only, use the [envault CLI](https://www.npmjs.com/package/@poyesis-tools/envault):
`envault run -e prod -- ./deploy.sh`.

## Server side

In the Envault dashboard, open the project (or platform), **Access**, **Add workload**, and enter the workflow's
identity with the environments it can resolve. A self-hosted Envault must first trust GitHub's tokens:
`WORKLOAD_ISSUERS='[{"issuer":"https://token.actions.githubusercontent.com","audience":"envault","kind":"github"}]'`.

The identity names the repository and the branch or tag (`ref`); pull requests have their own ref
(`refs/pull/<n>/merge`). Prefer the repository's numeric id:

- `github:repo_id:<repository_id>:ref:<ref>` (e.g. `github:repo_id:123456789:ref:refs/heads/main`): recommended. The id
  never comes back once a repository is deleted, so a new repository that reuses the name does not inherit the binding.
  Find it with `gh api repos/<owner>/<repo> --jq .id`.
- `github:repo:<owner>/<repo>:ref:<ref>` (e.g. `github:repo:acme/web:ref:refs/heads/main`): still accepted, but bound
  to a name: if the repository (or its owner) is deleted, renamed or transferred, whoever creates a repository with that
  name later gets its access. Existing name-based bindings keep working; move them to the id form when you can.

A token matches a binding in either form. On GitHub Enterprise Server the ids also name the issuer (its `name` in
`WORKLOAD_ISSUERS`): `github:<issuer name>:repo_id:<id>:ref:<ref>` / `github:<issuer name>:repo:<owner>/<repo>:ref:<ref>`,
so a repository on github.com is always a different principal.

## Safety

- All values are masked before anything is written to `$GITHUB_ENV` / `$GITHUB_OUTPUT`; the OIDC and Envault tokens are masked too.
- File commands use the `NAME<<DELIMITER` format with a random `ghadelimiter_<uuid>`; a value containing it is rejected.
- Names must match `[A-Za-z_][A-Za-z0-9_]*`; reserved names are never written to `$GITHUB_ENV` and are skipped with a warning: names that change how later steps start
  (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `DYLD_*`, `BASH_ENV`, `ENV`, `NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`,
  `PYTHONSTARTUP`, `PYTHONHOME`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`,
  `PATH`, `HOME`, `SHELL`, `IFS`, `PS4`, `PROMPT_COMMAND`, `GIT_*SSH*`, `GCONV_PATH`, `MALLOC_*`) and runner variables
  (`GITHUB_*`, `RUNNER_*`, `ACTIONS_*`, `CI`). Compared case-insensitively; the same list the Envault API refuses for new keys.
- 429/5xx and network errors are retried with backoff.

## Development

`dist/index.js` is hand-written, dependency-free CommonJS (no build step). `npm test`
runs it against a mock OIDC endpoint + API and checks mask ordering and the `GITHUB_ENV` format.
