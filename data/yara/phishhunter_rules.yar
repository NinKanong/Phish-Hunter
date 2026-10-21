rule PG_PowerShell_Download_Indicators {
    meta:
        description = "Static triage markers for PowerShell download activity"
        severity = "high"
        category = "script"
    strings:
        $a = "Invoke-WebRequest" nocase ascii wide
        $b = "DownloadString" nocase ascii wide
        $c = "Net.WebClient" nocase ascii wide
        $d = "-EncodedCommand" nocase ascii wide
    condition:
        2 of them
}

rule PG_Windows_LOLBin_Proxy_Indicators {
    meta:
        description = "Static triage markers for common signed binary proxy execution"
        severity = "medium"
        category = "windows"
    strings:
        $a = "rundll32" nocase ascii wide
        $b = "regsvr32" nocase ascii wide
        $c = "mshta" nocase ascii wide
        $d = "wmic" nocase ascii wide
    condition:
        2 of them
}

rule PG_PDF_Active_Content {
    meta:
        description = "Static PDF active-content triage markers"
        severity = "high"
        category = "document"
    strings:
        $a = "/JavaScript" ascii wide
        $b = "/OpenAction" ascii wide
        $c = "/Launch" ascii wide
        $d = "/EmbeddedFile" ascii wide
    condition:
        2 of them
}

rule PG_Office_Macro_Indicators {
    meta:
        description = "Static OOXML macro and embedded object markers"
        severity = "high"
        category = "office"
    strings:
        $a = "vbaProject.bin" nocase ascii wide
        $b = "externalLinks" nocase ascii wide
        $c = "embeddings" nocase ascii wide
    condition:
        1 of them
}
