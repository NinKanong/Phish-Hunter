from phishhunter.analyzers.file_analyzer import analyze_file
from phishhunter.analyzers.email_analyzer import analyze_email

def test_file_analysis():
    result=analyze_file("sample.bin",b"powershell.exe rundll32.exe example.com")
    assert result["hashes"]["sha256"]
    assert result["risk_score"]>0

def test_email_analysis():
    data=b"From: CEO <ceo@example.com>\nReply-To: help@evil.example\nSubject: Urgent verify your account\n\nPlease login immediately."
    result=analyze_email(data)
    assert result["risk_score"]>=25
