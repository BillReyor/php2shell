# Credits & Prior Work

This project's live RCE chain stands on the shoulders of several research efforts.
Credit where credit is due — in order of how directly they enabled this work.

## Direct foundations (the chain itself)

- **@alvarodh5** — single-file, pure-HTTP ASLR-bypassing RCE for PHP 8.5.11 x86_64 (MIT;
  the relevant code is inlined into [`exploit.py`](exploit.py) with attribution). The
  in-band Set-Cookie heap/libphp leaks (stages 1–2), the dangling `PS(http_session_vars)`
  reclaim, and the forged-frame geometry are all his. This project's chain ports that work to
  stock config + WordPress: chunked-TE arming for `post_max_size`, the Zend-MM slot-grid
  calibration (`k ≡ 6 mod 7`, pad-count knob), keep-alive worker targeting, black-box proof,
  and — beyond his PoC's 14-byte command limit — an extended carrier (measured in-lab with
  an allocator interposer) supporting commands up to ~305 chars. Without his chain there is no
  stage 3 here.

- **@9bie** — the original pure-HTTP ASLR-bypass chain for PHP 8.4.26 (Set-Cookie leaks +
  `zif_system` reclaim), plus the worker-pinning techniques and the legacy 8.4.26 research
  tree ([github.com/9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)).
  The in-band leak concept that made x64+ASLR exploitable at all comes from this line of work.

- **@dinosn** — PHP 8.5.11 dangling-reference reclaim geometry
  (`php-cve-2026-10961x-lab-poc`), referenced by @alvarodh5's port.

## Discovery & official analysis

- **Calif, OpenAI and Wiz** — discovery of CVE-2026-109618 / CVE-2026-109619 and the
  [php2shell write-up](https://calif.io/php2shell/): OOM-fatal-triggered memory-safety bugs
  in PHP core's RFC 1867 multipart path, pre-auth RCE on mod_php across WordPress, Drupal,
  Joomla, Laravel, Symfony and more.

- **The PHP security team** — official advisories (GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp),
  CVSS scoring, and the patches (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 + EOL backports). The
  8.5.12 fix diff was used here both for source analysis and as the Phase-2 control target.

## Context, validation & discovery of prior PoCs

- **VulnCheck** — [php2shell vulnerabilities blog](https://www.vulncheck.com/blog/php2shell-vulnerabilities):
  independent validation that ASLR can be bypassed for this CVE; key reference during the
  "is x64+ASLR even exploitable?" phase of this research.

- **CrowdStrike** — [Obstacles to weaponizing php2shell](https://www.crowdstrike.com/en-us/blog/obstacles-to-weaponizing-php2shell-likely-constrain-exploitation/):
  an excellent analysis of why turning the primitive into reliable RCE is hard; useful as a
  checklist of the exact problems this project had to solve (worker targeting, calibration
  transfer, app-stack interference).

- **mallory.ai** — vulnerability/PoC index used to locate and compare public PoCs.

- **Zer061** — pure-HTTP PoC referenced early in this research; its cross-request dangling
  primitive turned out not to work under stock prefork mod_php (source analysis showed
  `php_request_shutdown()` clears the session globals it depends on), which sharpened the
  question of what *does* survive request boundaries.

- **eness** — [heap-UAF PoC variant](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC)
  of the same handler; ships equivalent WAF/ModSecurity rules.

- **KillaBoi** — [StealMyBitcoin-PoC](https://github.com/KillaBoi/StealMyBitcoin-PoC): independent live
  exploitation (2026-10-25) against PHP 8.4.26 cli-server in a CTF context, using a different OOM
  vector (nested array names triggering `max_input_nesting_level`, ~250 KB wire size vs this project's
  ~128 MB arming). Corroborates the finding that client-visible error output during arming is what
  opens the leak channel.

## Development of this project

- **Qwen3.8 27B Abliterated by HuiHui** — AI research assistant (running in LM Studio
  Bionic): the exploit development across this effort — source-level mechanism decoding,
  interposer-based allocator ground truth, slot-grid calibration (`pads=112`), keep-alive
targeting design and validation, extended-carrier measurement, authorized live-target
  execution, and this repository's documentation.
## Disclaimer

All code here is for **lawful, authorized** security assessment, research and education only.
Do not run it against systems you do not own or lack explicit written permission to test.
The live-target results in this project were produced on an explicitly authorized test box.
