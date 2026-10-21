<?php
// php2shell demo — bare endpoint with NO session API usage at all.
// Proves the trigger is in PHP core (rfc1867 callback), not in app code:
// a multipart POST with the progress marker creates a session here even
// though this script never calls session_start().

header("Content-Type: text/plain");
echo "naked endpoint alive\n";
