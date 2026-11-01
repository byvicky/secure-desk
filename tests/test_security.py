from securedesk.security import redact_sensitive_data


def test_email_redaction():
    value = redact_sensitive_data("Contato: pessoa@example.com")
    assert "pessoa@example.com" not in value and "[EMAIL REDIGIDO]" in value


def test_cpf_redaction():
    value = redact_sensitive_data("CPF 123.456.789-00")
    assert "123.456.789-00" not in value and "[CPF REDIGIDO]" in value


def test_normal_text_unchanged():
    assert redact_sensitive_data("Meu computador não liga") == "Meu computador não liga"


def test_redacts_brazilian_phone():
    value = redact_sensitive_data("Ligue para (11) 98765-4321")
    assert "98765-4321" not in value and "[TELEFONE REDIGIDO]" in value
