# Maintenance — Revvity internal fork of credentials-binding

Branch `refresh-bound-credentials` is Revvity's internal fork of the Jenkins
`credentials-binding` plugin. It adds an opt-in "refresh bound credentials per step"
feature so that GitHub **App** installation tokens (1h TTL) stay valid across long
builds: for an admin-selected set of credential IDs, the bound value is re-resolved on
every step (fresh token) with masking on both the console and the exception/failure
surface. Empty selection ⇒ byte-for-byte upstream behaviour.

## Status
- **Upstream did NOT accept it.** Issue `jenkinsci/credentials-binding-plugin#545` was
  closed and PR `#546` set to CHANGES_REQUESTED ("complex change to a security-sensitive
  plugin; not the direction we want"; suggested alternative: mint the installation token
  on demand from the App private key inside the pipeline). → This is a **permanent internal
  fork** and must be rebased on each upstream release.
- Deployed on **jenkins.sss-alpha** as `credentials-binding` version
  **`728.v902a_273b_8947.1`** (replaces the official plugin; the version sorts above
  upstream so the update centre never offers a "downgrade" back to the official build).

## Patch surface (only these differ from upstream)
- `src/main/java/org/jenkinsci/plugins/credentialsbinding/refresh/`
  - `RefreshBindingConfiguration.java` — `GlobalConfiguration` with a **credential selector**
    (repeatable `Entry` + `<c:select>`); exposes `isRefreshing(String)` / `getCredentialIds()`.
  - `RefreshingOverrider.java` — re-resolves the binding on each `expand()` (per step).
  - `RefreshingFilter.java` — dynamic union masking (console).
  - `RefreshingFailureHandler.java` — masks refreshing secrets on the exception/failure surface.
  - `src/main/resources/.../refresh/**` — Jelly + help.
- `src/main/java/org/jenkinsci/plugins/credentialsbinding/impl/BindingStep.java` — the gate:
  allowlisted credential IDs take the refreshing path; everything else is byte-for-byte upstream.
- `pom.xml` — `<changelist>728.v902a_273b_8947.1</changelist>` (internal version).

## Build (JDK 21)
```
JAVA_HOME=$(/usr/libexec/java_home -v 21) mvn -q clean package
```
Produces `target/credentials-binding.hpi`. Build/test on JDK 21 (Homebrew's default JDK is too new).

## Deploy to jenkins.sss-alpha
`uploadPlugin` (UI/API) returns HTTP 500 when replacing a core plugin, so deploy via the filesystem:
```
scp target/credentials-binding.hpi inf-inst-dev-int-jenkins:/tmp/cb.hpi
ssh inf-inst-dev-int-jenkins 'JH=/var/lib/jenkins/plugins; \
  sudo cp /tmp/cb.hpi "$JH/credentials-binding.jpi"; \
  sudo chown jenkins:jenkins "$JH/credentials-binding.jpi"; \
  sudo rm -rf "$JH/credentials-binding"; sudo rm -f /tmp/cb.hpi'
```
Then a **safe restart** (waits for running jobs): `POST $JENKINS_URL/safeRestart`.
Configure the allowlist: *Manage Jenkins → Configure System → "Refresh bound credentials"* →
add the GitHub App credential IDs (`screening-ci`, `Github-Release-API-token`, `GITHUB_TOKEN`,
`Spotfire-CI`). Empty list = stock behaviour.

## Rebase onto a new upstream release
```
git fetch upstream
git rebase upstream/master refresh-bound-credentials     # or onto the specific new tag
# conflicts are usually only BindingStep.java + pom.xml <changelist>
JAVA_HOME=$(/usr/libexec/java_home -v 21) mvn -q clean verify
```
Keep `<changelist>` as `<upstream-version>.1` so the fork sorts just above the upstream it is based on.

## Rollback
Reinstall the official `credentials-binding` + clear the allowlist; restart.
