# Patching CVE-2026-111497 in Node.js

This guide explains how to remove exposure to the Node.js Brotli decoder
out-of-bounds write tracked as CVE-2026-111497. The permanent fix is to replace
the affected Node.js runtime, rebuild every artifact that embeds it, restart
all running processes, and verify the runtime inside the deployed workload.

Updating Express, `body-parser`, or another npm dependency alone does not patch
the vulnerable decoder bundled with Node.js.

## Fixed Node.js releases

Use the newest supported security release available for your chosen release
line. The first Node.js releases containing the fix are:

| Release line | First fixed release |
|---|---|
| Node.js 22.x | `22.23.4` |
| Node.js 24.x | `24.22.1` |
| Node.js 26.x | `26.12.1` |

All end-of-life Node.js lines should be migrated to a supported line instead of
being treated as safe because they are absent from the table.

Node.js `24.22.1` may still report `process.versions.brotli` as `1.2.0` because
the Node.js security release cherry-picked the upstream fix into its bundled
decoder. Determine fixed status from the Node.js security-release version, not
from the Brotli version string alone.

## 1. Identify affected workloads

Check the runtime used by the running application, not only the version
installed on the build host:

```bash
node --version
node -p '"node=" + process.version + " brotli=" + process.versions.brotli'
node -p 'process.execPath'
```

For a containerized service:

```bash
APP_CONTAINER=my-node-service
docker exec "$APP_CONTAINER" node --version
docker exec "$APP_CONTAINER" node -p \
  '"node=" + process.version + " brotli=" + process.versions.brotli'
```

Review whether the application processes attacker-controlled Brotli data,
including:

- inbound requests carrying `Content-Encoding: br`;
- direct use of `node:zlib` Brotli decompression APIs;
- middleware that automatically inflates compressed request bodies;
- HTTP clients or import jobs that decode Brotli responses from untrusted
  endpoints; and
- workers, serverless bundles, desktop applications, or appliances that embed
  their own Node.js runtime.

Do not rely on `npm audit` alone. This issue is in the runtime component and may
not appear in the application's npm dependency tree.

## 2. Patch a container image

Change the production base image to a fixed or later supported release. For a
Node.js 24 deployment, the minimum patched example is:

```dockerfile
FROM node:24.22.1-bookworm-slim
```

If the Dockerfile accepts the base image as a build argument:

```bash
docker pull node:24.22.1-bookworm-slim

docker build --pull --no-cache \
  --build-arg NODE_IMAGE=node:24.22.1-bookworm-slim \
  -t my-service:node2shell-patched .

docker run --rm my-service:node2shell-patched node --version
```

The version check must report `v24.22.1` or a later supported security release.
Use `--pull` and rebuild without cache so an older runtime layer cannot be
silently reused.

For reproducible production builds, resolve the reviewed image to its registry
digest and pin that patched digest after testing:

```bash
docker image inspect \
  --format '{{json .RepoDigests}}' node:24.22.1-bookworm-slim
```

Do not reuse the vulnerable digest from this reproduction lab.

## 3. Patch this repository's fixed control

The `fixed` service already uses Node.js `24.22.1`. Rebuild it from the patched
base image and recreate the service:

```bash
docker compose build --pull --no-cache fixed
docker compose up -d --force-recreate fixed

docker compose exec -T fixed node --version
curl -fsS http://127.0.0.1:3002/api/v1/version
```

Expected runtime evidence:

```text
v24.22.1
{"service":"orbital","node":"v24.22.1"}
```

The `vuln` service intentionally remains pinned to Node.js `24.22.0` for the
loopback-only A/B lab. Never deploy that service or its image outside the local
research environment.

## 4. Patch a host installation

Use the same installation method that owns the existing Node.js runtime. Avoid
mixing a version manager, distribution package, and manual binary in one
service because the daemon may continue using a different `node` executable.

Example with `nvm` for the Node.js 24 line:

```bash
nvm install 24.22.1 --reinstall-packages-from=24.22.0
nvm alias default 24.22.1
nvm use 24.22.1

node --version
node -p 'process.execPath'
```

For a system service, restart it after updating the runtime and then inspect the
version from the service's real execution environment:

```bash
NODE_SERVICE=my-node-service
sudo systemctl restart "$NODE_SERVICE"
sudo systemctl status "$NODE_SERVICE" --no-pager
```

If the application vendors Node.js inside its own directory or executable,
rebuild and redeploy the application. Updating a separate system-wide Node.js
installation will not replace an embedded runtime.

## 5. Patch Kubernetes workloads

Build and publish an application image based on a fixed Node.js release, then
update the workload to that image:

```bash
kubectl set image deployment/my-service \
  app=registry.example/my-service:node2shell-patched

kubectl rollout status deployment/my-service
kubectl exec deployment/my-service -c app -- node --version
```

Confirm every replica has rolled over. A successful rollout is not sufficient
if old pods, jobs, cron jobs, or worker deployments still run an affected
image.

## 6. Temporary mitigation when upgrade is delayed

The following measures reduce exposure but do not replace the runtime update:

1. Reject inbound requests whose `Content-Encoding` includes `br` before they
   reach Node.js.
2. Disable Brotli decompression for untrusted responses, imports, and message
   payloads.
3. Restrict affected endpoints to trusted networks where operationally
   possible.
4. Apply conservative compressed and decompressed body-size limits as
   defense-in-depth.

Example NGINX rejection rule:

```nginx
server {
    if ($http_content_encoding ~* "(^|,)\\s*br(\\s*,|$)") {
        return 415;
    }

    # Existing proxy configuration follows.
}
```

Reject the request; do not merely strip the `Content-Encoding` header and pass
the still-compressed body upstream. Body-size limits may block the public lab
payload, but they are not a complete fix for the underlying memory-corruption
bug.

## 7. Verify the deployed fix

Verification should combine version evidence, functional tests, and a controlled
negative security test.

### Runtime evidence

```bash
node --version
node -p '"node=" + process.version + " brotli=" + process.versions.brotli'
```

For containers, run those commands inside the running container or pod. Do not
accept the CI runner's version as proof of the deployed version.

### Functional validation

- Exercise health checks and normal compressed-request workflows.
- Confirm clients receive an intentional `415 Unsupported Media Type` if the
  temporary Brotli block remains enabled.
- Review application and supervisor logs for crashes or restart loops.
- Confirm all replicas and background workers use the patched runtime.

### Negative test in this local lab

Start the A/B lab, then send the same shell-activation payload to the patched
control:

```bash
./run.sh
python3 ./poc.py --port 3002 --validate-shell --attempts 32
```

Expected result:

```text
[-] FAIL: RCE did not land in 32 attempts
```

In this context, `FAIL` is the correct security result: the PoC did not obtain
code execution. Run exploit validation only against the loopback lab or another
environment you are explicitly authorized to test. Do not run it against a
production service.

A negative PoC result alone is not patch evidence because exploit reliability
can vary by build. The deployed Node.js version must also be a fixed or later
supported release.

## 8. Rollout and rollback guidance

Use a canary or staged rollout where possible:

1. Build the application on the patched runtime.
2. Run unit, integration, and compressed-payload compatibility tests.
3. Deploy a canary and verify its runtime from inside the workload.
4. Roll out all web, worker, job, and scheduled-task instances.
5. Monitor crash rate, HTTP 4xx/5xx rate, latency, and restart count.
6. Record the image digest and runtime evidence for the change ticket.

Prepare rollback artifacts by rebuilding the previous application revision on
the patched Node.js runtime. Do not roll back to an image that restores an
affected runtime.

## 9. Post-patch security review

Because the vulnerability can corrupt memory and potentially lead to remote
code execution, investigate unexplained Node.js crashes or restart loops that
occurred while an affected decoder was exposed to untrusted data. Preserve
relevant logs, rebuild from trusted artifacts, and rotate credentials available
to the affected workload if compromise is suspected.

## Patch completion checklist

- [ ] Every deployed Node.js runtime is a fixed or later supported release.
- [ ] Container images were rebuilt with `--pull` and without stale runtime
      layers.
- [ ] All processes, containers, pods, workers, and scheduled jobs restarted.
- [ ] Runtime versions were checked inside the deployed workloads.
- [ ] Application compatibility and health checks passed.
- [ ] Controlled negative testing did not obtain code execution.
- [ ] Temporary mitigations are documented and removed only after rollout is
      complete.
- [ ] Patched image digests and deployment evidence are retained.
- [ ] Rollback artifacts also contain the patched runtime.

## References

- [Node.js October 2026 Security Releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [Node.js v24.22.1 security release](https://nodejs.org/en/blog/release/v24.22.1)
- [Upstream Brotli fix](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)
- [Brotli v1.2.1 release](https://github.com/google/brotli/releases/tag/v1.2.1)
