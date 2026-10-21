from __future__ import annotations

import asyncio
import io
import zipfile

from phishhunter.analyzers.email_analyzer import analyze_email
from phishhunter.analyzers.file_analyzer import analyze_file, pdf_metadata
from phishhunter.utils import http as http_utils
from phishhunter.security.csrf import signed_report_token, verify_report_token
from phishhunter.security.upload_guard import read_upload_limited, sanitize_filename
from phishhunter_common.hash import hash_bytes
from phishhunter_common.ioc import extract_iocs


def test_hash_engine_has_multiple_independent_digests():
    result = hash_bytes(b"phishhunter")
    assert set(result) == {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "blake2b_256"}
    assert all(len(value) > 0 for value in result.values())


def test_defanged_ioc_extraction():
    result = extract_iocs("hxxps[:]//evil.example/login hxxp://one.example 8.8.8.8")
    assert "https://evil.example/login" in result["urls"]
    assert "http://one.example" in result["urls"]
    assert "evil.example" in result["domains"]
    assert "8.8.8.8" in result["ips"]


def test_pdf_active_content_is_recorded():
    data = b"%PDF-1.7\n1 0 obj << /OpenAction /JavaScript /JS (app.alert(1)) /EmbeddedFile >> endobj"
    metadata = pdf_metadata(data)
    assert metadata["indicators"]["javascript"] == 2
    assert metadata["suspicious"] is True


def test_office_macro_and_external_links_are_detected_without_extracting_files():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/vbaProject.bin", b"macro placeholder")
        zf.writestr("word/_rels/document.xml.rels", "<Relationships/>")
        zf.writestr("word/externalLinks/externalLink1.xml", "http://evil.example")
    result = analyze_file("invoice.docx", output.getvalue())
    assert result["metadata"]["office"]["vba_project"] is True
    assert result["metadata"]["office"]["external_links"]
    assert result["risk_score"] >= 18
    assert result["correlation"]["actor_attribution"]["status"] == "withheld"


def test_email_auth_headers_attachments_and_link_mismatch():
    data = (
        b"From: Finance <finance@example.com>\r\n"
        b"Reply-To: attacker@evil.example\r\n"
        b"Authentication-Results: mx.example; spf=fail dkim=fail dmarc=fail\r\n"
        b"Subject: Urgent verify your account\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=abc\r\n\r\n"
        b"--abc\r\nContent-Type: text/html\r\n\r\n"
        b"<a href='https://evil.example/login'>https://example.com/login</a>"
        b"<form action='https://evil.example/collect'><input name='password' type='password'></form>\r\n"
        b"--abc\r\nContent-Disposition: attachment; filename=invoice.exe\r\n"
        b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        b"TVo=\r\n--abc--\r\n"
    )
    result = analyze_email(data)
    assert result["auth"]["spf_result"] == "fail"
    assert result["auth"]["dkim_result"] == "fail"
    assert result["auth"]["dmarc_result"] == "fail"
    assert "From and Reply-To domains differ" in result["mismatches"]
    assert result["attachments"][0]["dangerous_extension"] is True
    assert result["links"][0]["domain_mismatch"] is True
    assert result["forms"][0]["password_field"] is True
    assert result["risk_score"] >= 55


def test_upload_path_defense():
    for value in ("../evil.exe", "..\\evil.exe", "/tmp/evil.exe", "C:\\temp\\evil.exe", "\x01evil.exe"):
        try:
            sanitize_filename(value)
        except ValueError:
            continue
        raise AssertionError(f"unsafe filename accepted: {value!r}")


class _FakeUpload:
    def __init__(self, data: bytes):
        self._stream = io.BytesIO(data)

    async def read(self, size: int):
        return self._stream.read(size)


def test_upload_reader_enforces_a_hard_memory_bound():
    async def run():
        ok = await read_upload_limited(_FakeUpload(b"abc"), 3, chunk_size=2)
        assert ok == b"abc"
        try:
            await read_upload_limited(_FakeUpload(b"abcd"), 3, chunk_size=2)
        except ValueError:
            return
        raise AssertionError("oversized upload was accepted")

    asyncio.run(run())


def test_manual_redirect_pipeline_revalidates_each_hop(monkeypatch):
    calls = []
    responses = [
        {"status_code": 302, "headers": {"location": "https://second.example/path"}, "final_url": "https://first.example"},
        {"status_code": 200, "headers": {}, "final_url": "https://second.example/path", "content": "ok", "content_length": 2, "truncated": False},
    ]

    monkeypatch.setattr(http_utils, "validate_url", lambda value: calls.append(("validate", value)) or value)
    monkeypatch.setattr(http_utils, "resolve_and_validate", lambda host, port: ["203.0.113.10"])
    monkeypatch.setattr(http_utils, "_fetch_once", lambda url, ip: responses.pop(0) | {"resolved_ip": ip})

    result = asyncio.run(http_utils.fetch_url("https://first.example"))
    assert result["redirect_count"] == 1
    validated = [value for action, value in calls if action == "validate"]
    assert validated == ["https://first.example", "https://first.example", "https://second.example/path", "https://second.example/path"]


def test_report_share_token_is_tamper_evident():
    token = signed_report_token(7, 42)
    assert verify_report_token(token, 7, 42)
    assert not verify_report_token(token + "a", 7, 42)
    assert not verify_report_token(signed_report_token(7, 43), 7, 42)
