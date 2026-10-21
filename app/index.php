<?php
// php2shell demo — the "victim" application.
//
// Deliberately ordinary: stock session usage, nothing special in the app code.
// The vulnerability lives in PHP CORE (the session upload-progress handler,
// php_session_rfc1867_callback), which runs during request-body parsing —
// BEFORE this file ever executes. Frameworks never get a chance to intervene.

session_start(); // all stock defaults (use_only_cookies=On, etc.)

if (isset($_GET['login'])) {
    // "authentication" — stamps identity into whatever session it was given.
    $_SESSION['user'] = 'admin';
    $_SESSION['role'] = 'superuser';
    $_SESSION['api_key'] = 'SECRET-9f2b-demo';
}

// Flag attacker-injected upload-progress keys (the P2 artifact).
$injected = array();
foreach (array_keys($_SESSION) as $k) {
    if (strpos((string)$k, 'upload_progress_') === 0) $injected[] = $k;
}
?>
<!doctype html>
<html><head><meta charset="utf-8"><title>Acme Intranet</title>
<style>
 body{font-family:-apple-system,system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#222}
 code,pre{background:#f4f4f8;border-radius:6px;font-size:13px}
 pre{padding:12px;overflow:auto}
 .warn{color:#b00020;font-weight:600}
 h1 small{color:#888;font-weight:400}
</style></head>
<body>
<h1>Acme Intranet <small>(php2shell demo victim)</small></h1>
<?php if (!empty($_SESSION['user'])): ?>
  <p>Hello, <b><?= htmlspecialchars($_SESSION['user']) ?></b> — role:
     <code><?= htmlspecialchars((string)($_SESSION['role'] ?? '')) ?></code></p>
  <p>api_key: <code><?= htmlspecialchars((string)($_SESSION['api_key'] ?? '')) ?></code></p>
<?php else: ?>
  <p>You are not logged in. <a href="?login=1">Log in as admin</a></p>
<?php endif; ?>

<hr>
<h2>Session inspector <small>(what PHP core knows about this session)</small></h2>
<p>SID: <code><?= htmlspecialchars(session_id()) ?></code></p>
<pre><?= htmlspecialchars(json_encode($_SESSION, JSON_PRETTY_PRINT)) ?></pre>
<?php if ($injected): ?>
  <p class="warn">&#9888; attacker-injected upload_progress_* key(s) present:
     <?= htmlspecialchars(implode(', ', $injected)) ?></p>
<?php endif; ?>
</body></html>
