# Screenshot checklist

Save these into `docs/screenshots/` using the exact filenames below — they're wired directly into `README.md`.

| Filename | Section | What to capture |
|---|---|---|
| `vm-network-config.png` | 1. Network & VMs | VMware network editor or VM settings showing the custom VMnet2 config |
| `static-ip-confirmed.png` | 1. Network & VMs | `ip -brief address` on Ubuntu or `ipconfig` on Windows showing the static IPs |
| `ufw-rules.png` | 1. Network & VMs | `sudo ufw status numbered` — the hardened, source-scoped firewall rules |
| `wazuh-install-success.png` | 2. Deploying Wazuh | The all-in-one installer's final summary block with generated credentials |
| `cert-mismatch-error.png` | 3. TLS fix | The original `IP address mismatch` / `unable to verify` error |
| `cert-san-fixed.png` | 3. TLS fix | `openssl x509 -noout -ext subjectAltName` showing the corrected IP |
| `tls-verify-ok.png` | 3. TLS fix | `Verify return code: 0 (ok)` from `openssl s_client` |
| `agent-zero-agents.png` | 4. FIM proof | Wazuh dashboard showing 0 agents (before enrollment) |
| `agent-connected.png` | 4. FIM proof | Wazuh dashboard or `agent_control -lc` showing `windows-laptop` Active |
| `fim-config-applied.png` | 4. FIM proof | `Select-String` output confirming the `<directories>` FIM entry |
| `fim-alert-chain.png` | 4. FIM proof | The `jq`-filtered added/modified/deleted alert output (the "best screenshot" one) |
| `netalertx-banner.png` | 5. NetAlertX | The ASCII art startup banner in `docker logs` |
| `netalertx-empty.png` | 5. NetAlertX | NetAlertX UI showing "No devices found yet" |
| `netalertx-populated.png` | 5. NetAlertX | NetAlertX UI showing all 5 discovered devices |
| `gemini-api-test.png` | 6. AI analyst | Raw `curl` test to Gemini returning `"OK"` or the sample JSON analysis |
| `forwarder-service-live.png` | 6. AI analyst | `journalctl -u wazuh-gemini-forwarder` showing "Serving Grafana API on..." |
| `ai-analysis-full.png` | 6. AI analyst | Full `/api/latest` JSON response — the rich risk-score + evidence output |
| `grafana-ds-wazuh.png` | 7. Grafana | Wazuh OpenSearch data source "Save & test" success message |
| `grafana-ds-netalertx.png` | 7. Grafana | NetAlertX Infinity data source health check success |
| `panel-fim-events.png` | 7. Grafana | The FIM Events stat panel showing a real count |
| `panel-device-inventory.png` | 7. Grafana | The Device Inventory table panel populated |
| `panel-ai-gauge.png` | 7. Grafana | The Latest AI Risk Score gauge |
| `panel-ai-table.png` | 7. Grafana | The Latest AI Analysis table panel |
| `dashboard-full.png` | 8. Final result (+ hero image) | The complete 6-panel dashboard, all live |
| `systemd-override-fix.png` | Engineering notes | The `systemctl edit` boot-race-condition fix |

## Notes

- Crop tightly, hide/blur any real passwords, API keys, or tokens still visible in terminal history before saving.
- `dashboard-full.png` is used twice (top of README as hero image, and again at the end) — same file works for both.
- If a slot doesn't have a good matching screenshot, it's fine to delete that `<img>` line from `README.md` rather than force a bad fit.
