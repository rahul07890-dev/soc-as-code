rule WebShell_Detection
{
    meta:
        description = "Detects common webshell patterns"
        author = "SOC Team"
        date = "2024-12-03"
        severity = "high"
    
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell.exe" nocase
        $php_exec = "exec(" nocase
        $php_system = "system(" nocase
        $php_shell = "shell_exec(" nocase
        $upload = "move_uploaded_file" nocase
        $eval = "eval(" nocase
        
    condition:
        ($upload or $eval) and 2 of ($cmd*, $php_*)
}