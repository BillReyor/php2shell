<?php
// php2shell demo — the LFI sink.
//
// Represents the common vulnerable-app pattern: dynamic include of a
// user-influenced path (page router / template loader / debug helper).
//
// Attack: the exploit places a PHP payload at a DETERMINISTIC path —
// <save_path>/sess_<sid>, where the sid is attacker-chosen (P1) and the
// payload rides in an upload filename (P2), persisted because the multipart
// parse bailed before cleanup (P3). Including that file executes any <?php
// block it contains. This is the verified pre-auth RCE chain (19h, "R").

header("Content-Type: text/plain");
$page = $_GET['page'] ?? null;
if ($page === null) {
    echo "sink armed. no page selected.\n";
    exit;
}
include($page);
