/*
   RatSweepr bundled YARA rules — WordPress webshell & backdoor detection.
   Self-contained (no includes). Operators can supplement with maintained
   rulesets (php-malware-finder, signature-base) via RS_YARA_RULES=/path.
*/

rule RS_eval_user_input {
    meta:
        description = "eval/assert of user-controlled input"
        severity = "HIGH"
    strings:
        $a = /(eval|assert)\s*\(\s*(stripslashes\s*\()?\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $b = /(eval|assert)\s*\(\s*\$[a-zA-Z_]+\s*\)/ nocase
    condition:
        any of them
}

rule RS_command_exec_user_input {
    meta:
        description = "OS command execution with user input"
        severity = "HIGH"
    strings:
        $a = /(system|passthru|shell_exec|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $b = /(system|passthru|shell_exec)\s*\(\s*["']?\s*\$_(GET|POST|REQUEST)/ nocase
    condition:
        any of them
}

rule RS_obfuscated_eval_chain {
    meta:
        description = "eval of decoded/inflated payload"
        severity = "HIGH"
    strings:
        $a = /eval\s*\(\s*(gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(/ nocase
        $b = /\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*(gzinflate|gzuncompress)\s*\(\s*base64_decode/ nocase
    condition:
        any of them
}

rule RS_hex_obfuscated_hooks {
    meta:
        description = "WordPress hook names hex-escaped to evade grep (nulled/backdoor)"
        severity = "HIGH"
    strings:
        $a = /add_(action|filter)\s*\(\s*["'](\\x[0-9a-fA-F]{2}|\\[0-9]{2,3}){4,}/ nocase
    condition:
        $a
}

rule RS_fake_wordpress_plugin {
    meta:
        description = "Plugin falsely attributed to WordPress.org"
        severity = "HIGH"
    strings:
        $a = /Author URI:\s*https?:\/\/wordpress\.org\/#/ nocase
        $b = "Official WordPress plugin" nocase
    condition:
        any of them
}

rule RS_self_hiding_plugin {
    meta:
        description = "Plugin hides itself from the admin plugin list"
        severity = "HIGH"
    strings:
        $a = /unset\s*\([^)]*wp_list_table->items/ nocase
        $b = /unset\s*\(\s*\$[a-zA-Z_]+\[['"][^]]*\/[^]]*\.php['"]\s*\]\s*\)\s*;/
    condition:
        any of them
}

rule RS_php_in_disguise {
    meta:
        description = "PHP code with image/asset header (fake image shell)"
        severity = "HIGH"
    strings:
        $gif = /^GIF8[79]a/
        $php = "<?php"
    condition:
        $gif at 0 and $php
}

rule RS_hmac_authed_backdoor {
    meta:
        description = "HMAC-authenticated request handler feeding eval (RAT)"
        severity = "HIGH"
    strings:
        $h = /hash_hmac\s*\(\s*["']sha256["'][^)]*\$_(POST|GET|SERVER|REQUEST)/ nocase
        $e = /eval\s*\(\s*base64_decode/ nocase
    condition:
        $h and $e
}

rule RS_uploader_shell {
    meta:
        description = "File uploader (potential webshell dropper)"
        severity = "MEDIUM"
    strings:
        $a = /move_uploaded_file\s*\([^)]*\$_FILES/ nocase
        $b = /\$_FILES\[[^]]+\]\[['"]tmp_name/ nocase
    condition:
        all of them
}

rule RS_large_base64_payload {
    meta:
        description = "Large base64 blob decoded (packed payload)"
        severity = "HIGH"
    strings:
        $a = /base64_decode\s*\(\s*["'][A-Za-z0-9+\/]{200,}/ nocase
    condition:
        $a
}
