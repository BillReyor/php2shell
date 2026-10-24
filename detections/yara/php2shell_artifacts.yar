/*
 * php2shell (CVE-2026-109618 / CVE-2026-109619) — YARA rules
 * -----------------------------------------------------------------------------
 * On-disk and in-memory artifacts of the PHP session.upload_progress abuse
 * chain. Scan targets:
 *   - session.save_path (e.g. /var/lib/php/sessions, /tmp)  -> sess_* files
 *   - web roots / uploads                                   -> dropped webshells
 *   - process memory / core dumps                           -> forged structures
 *   - staging boxes during IR                               -> the PoC tooling
 *
 * The poisoned-session rules are the high-value ones: they describe the
 * attacker's persisted primitive, not any specific PoC. The tooling rule is for
 * triage/attribution on hosts you control, not for attack-traffic detection.
 */

rule php2shell_poisoned_session_file
{
    meta:
        description = "PHP session file carrying an injected upload_progress_ key with an embedded PHP tag (php2shell poison carrier)"
        reference   = "https://calif.io/php2shell/"
        cve         = "CVE-2026-109618, CVE-2026-109619"
        confidence  = "high"
        author      = "php2shell detections"
        date        = "2026-10-24"
    strings:
        $progress = "upload_progress_" ascii
        $php1     = "<?php" ascii nocase
        $php2     = "<?=" ascii
        $sys      = /system\s*\(/ ascii nocase
        $exec     = /(exec|shell_exec|passthru|popen|proc_open)\s*\(/ ascii nocase
    condition:
        // PHP session serialization uses "<key>|<serialized-value>"; a progress
        // key next to executable PHP in a sess_ file is the poison.
        $progress and (any of ($php1, $php2) or $sys or $exec)
}

rule php2shell_session_webshell
{
    meta:
        description = "PHP session file containing an executable PHP block with command execution (LFI-include RCE target of php2shell)"
        reference   = "https://calif.io/php2shell/"
        cve         = "CVE-2026-109618, CVE-2026-109619"
        confidence  = "medium"
        author      = "php2shell detections"
        date        = "2026-10-24"
    strings:
        $tag  = "<?php" ascii nocase
        $c1   = /system\s*\(/ ascii nocase
        $c2   = /\b(shell_exec|exec|passthru|eval|assert)\s*\(/ ascii nocase
        $c3   = "$_GET[" ascii
        $c4   = "$_REQUEST[" ascii
        $c5   = "$_POST[" ascii
    condition:
        // Session storage should never contain PHP source. A sess_ file with a
        // PHP tag plus an exec sink is a dropped webshell regardless of vector.
        $tag and (any of ($c1, $c2)) and 1 of ($c3, $c4, $c5)
}

rule php2shell_forged_call_record
{
    meta:
        description = "Forged zend_fcall_info / fake-structure record with embedded system command (php2shell heap-UAF / full-RCE primitive)"
        reference   = "https://calif.io/php2shell/ ; eness PoC ; 9bie/dinosn"
        cve         = "CVE-2026-109618"
        confidence  = "medium"
        author      = "php2shell detections"
        date        = "2026-10-24"
    strings:
        // ASCII command primitive planted in the reclaimed string bin
        $sysnul = "system\x00" ascii
        $binsh  = "/bin/sh" ascii
        // IS_STRING_EX (0x106) / IS_OBJECT_EX (0x308) zval type tags used by the
        // forge records, packed little-endian near the start of the blob.
        $t_str  = { 06 01 00 00 }
        $t_obj  = { 08 03 00 00 }
    condition:
        $sysnul and 1 of ($binsh, $t_str, $t_obj)
}

rule php2shell_poc_tooling
{
    meta:
        description = "php2shell public PoC / exploit tooling (triage & attribution on controlled hosts — NOT an attack-traffic signature)"
        reference   = "https://calif.io/php2shell/"
        cve         = "CVE-2026-109618, CVE-2026-109619"
        confidence  = "informational"
        author      = "php2shell detections"
        date        = "2026-10-24"
    strings:
        $f1 = "PHP_SESSION_UPLOAD_PROGRESS" ascii
        $m1 = "php2shell" ascii nocase
        $m2 = "zend_call_function" ascii
        $m3 = "zval_ptr_dtor" ascii
        $m4 = "JACKALPOC" ascii
        $m5 = "php_session_rfc1867_callback" ascii
        $m6 = "dangling PS(" ascii
    condition:
        $f1 and 2 of ($m1, $m2, $m3, $m4, $m5, $m6)
}
