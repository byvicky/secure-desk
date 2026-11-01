from securedesk.triage import analyze, classify, prioritize


def test_phishing_is_critical():
    category, priority = analyze("E-mail suspeito", "Recebi um phishing com link malicioso")
    assert category == "seguranca" and priority == "critica"


def test_access_classification():
    assert classify("Não consigo fazer login", "Minha senha foi bloqueada") == "acesso"


def test_explicit_category():
    assert classify("Computador lento", "Sistema lento", "hardware") == "hardware"


def test_generic_is_low():
    assert prioritize("Dúvida sobre programa", "Preciso de orientação", "outro") == "baixa"
