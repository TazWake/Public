/*
    webshells.yar - Halkyn Consulting Friday Threat Hunting series
    =============================================================
    Original, behaviour-based YARA rules for common web shell families across
    PHP, JSP and ASPX. The design principle throughout is "capability AND
    context": a rule fires only when a dangerous primitive (exec/eval) appears
    together with attacker-controllable request input, because that combination
    is what a web shell needs and what ordinary application code rarely shows.
    This keeps the false-positive rate against real frameworks low.

    These rules encode published *concepts* (the primitives and shapes web
    shells rely on); they contain no third-party rule text.

    Licence: MIT. Author: Halkyn Consulting.
*/

private rule is_php
{
    strings:
        $php = "<?php"
        $php_short = "<?="
    condition:
        any of them
}

rule HALKYN_Webshell_PHP_Eval_Request
{
    meta:
        author      = "Halkyn Consulting"
        description = "PHP that passes request input to an execution/eval primitive"
        concept     = "web shell = attacker input -> code/command execution"
        severity    = "high"
        family      = "generic-php-webshell"
        date        = "2026-08"
    strings:
        // execution / evaluation primitives
        $exec1 = "eval("        nocase
        $exec2 = "assert("      nocase
        $exec3 = "system("      nocase
        $exec4 = "passthru("    nocase
        $exec5 = "shell_exec("  nocase
        $exec6 = "proc_open("   nocase
        $exec7 = "popen("       nocase
        $exec8 = /preg_replace\s*\(\s*["'].*\/e/ nocase   // classic /e modifier
        // attacker-controllable request input
        $req1 = "$_GET"     nocase
        $req2 = "$_POST"    nocase
        $req3 = "$_REQUEST" nocase
        $req4 = "$_COOKIE"  nocase
        $req5 = "$_SERVER['HTTP_" nocase
        $req6 = "php://input" nocase
    condition:
        is_php and filesize < 200KB
        and any of ($exec*) and any of ($req*)
}

rule HALKYN_Webshell_PHP_Obfuscated
{
    meta:
        author      = "Halkyn Consulting"
        description = "PHP decode-and-execute: a decoder feeding an evaluator"
        concept     = "packed web shells stack base64/gzinflate/rot13 into eval"
        severity    = "high"
        family      = "obfuscated-php"
        date        = "2026-08"
    strings:
        $eval1 = "eval("   nocase
        $eval2 = "assert(" nocase
        $eval3 = "create_function(" nocase
        $dec1 = "base64_decode(" nocase
        $dec2 = "gzinflate("     nocase
        $dec3 = "gzuncompress("  nocase
        $dec4 = "str_rot13("     nocase
        $dec5 = "gzdecode("      nocase
    condition:
        is_php and filesize < 500KB
        and any of ($eval*) and any of ($dec*)
}

rule HALKYN_Webshell_JSP_Exec
{
    meta:
        author      = "Halkyn Consulting"
        description = "JSP that runs a process from request input"
        concept     = "Runtime.exec / ProcessBuilder driven by request parameter"
        severity    = "high"
        family      = "jsp-webshell"
        date        = "2026-08"
    strings:
        $jsp = "<%"
        $exec1 = "Runtime.getRuntime().exec" nocase
        $exec2 = "ProcessBuilder"            nocase
        $req1 = "request.getParameter"       nocase
        $req2 = "request.getHeader"          nocase
    condition:
        $jsp and filesize < 200KB
        and any of ($exec*) and any of ($req*)
}

rule HALKYN_Webshell_ASPX_Exec
{
    meta:
        author      = "Halkyn Consulting"
        description = "ASP/ASPX that runs a process or evaluates request input"
        concept     = "Process.Start / eval driven by Request in a server page"
        severity    = "high"
        family      = "aspx-webshell"
        date        = "2026-08"
    strings:
        $page1 = "<%@ Page"   nocase
        $page2 = "<%@Page"    nocase
        $page3 = "runat=\"server\"" nocase
        $exec1 = "System.Diagnostics.Process" nocase
        $exec2 = "Process.Start"  nocase
        $exec3 = "eval("          nocase
        $exec4 = "cmd.exe"        nocase
        $req1 = "Request["        nocase
        $req2 = "Request.Form"    nocase
        $req3 = "Request.QueryString" nocase
    condition:
        any of ($page*) and filesize < 200KB
        and any of ($exec*) and any of ($req*)
}
