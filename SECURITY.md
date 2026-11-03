# Política de segurança

Obrigado por ajudar a manter o SecureDesk seguro.

## Escopo

O SecureDesk é um projeto educacional em desenvolvimento. Não envie dados pessoais reais, credenciais, tokens ou informações confidenciais ao testar a aplicação.

## Como reportar uma vulnerabilidade

Não publique detalhes de uma possível vulnerabilidade em uma issue pública. Entre em contato com a pessoa mantenedora pelo canal privado disponibilizado no perfil do GitHub, incluindo:
- descrição do problema e impacto potencial;
- passos mínimos para reproduzir;
- versão ou commit afetado;
- sugestão de mitigação, se houver.

Não inclua dados de terceiros, segredos ou provas de conceito destrutivas.

## Limitações conhecidas

- O limitador de requisições usa SQLite e compartilha o estado entre processos que acessam o mesmo arquivo no mesmo host. Ele não coordena múltiplos hosts e não substitui controles de borda.
- A redação de dados depende de padrões conhecidos e não detecta todo tipo de informação pessoal. Os novos registros de solicitantes, títulos, descrições e comentários passam por redação heurística; dados históricos exigem auditoria explícita.
- O limite padrão do corpo HTTP é 1 MiB e pode ser configurado por `SECUREDESK_MAX_REQUEST_BODY_BYTES`. A aplicação rejeita corpos maiores com HTTP 413.
- Se o armazenamento SQLite do limitador estiver indisponível, as requisições são bloqueadas com HTTP 503 (fail closed), inclusive tentativas de login.
- Respostas de validação HTTP 422 omitem o valor original dos campos rejeitados para evitar ecoar senhas, tokens ou dados pessoais.
- O cookie de sessão tem validade máxima de oito horas, usa `HttpOnly` (padrão do middleware), `SameSite=Strict` e `Secure` em produção. O logout limpa a sessão; contas inativas ou com papel alterado têm a sessão rejeitada na próxima requisição.
- O script `python -m scripts.audit_pii --database CAMINHO` faz auditoria somente leitura e exibe apenas contagens. Após revisar o relatório e fazer uma cópia segura, `--apply` cria um backup SQLite e mascara padrões reconhecidos. A operação é heurística e deve ser validada em uma cópia antes de ser aplicada em dados importantes.
- A chave Bearer compartilhada é um mecanismo de demonstração, não um sistema completo de identidade e autorização.
- O projeto ainda não foi aprovado para processar dados reais ou operar em produção.
- A política CSP e os cabeçalhos HTTP básicos estão ativos; a política deve ser reavaliada sempre que novos recursos externos forem adicionados.
- O workflow de auditoria de dependências Python usa `pip-audit`; o Dependabot verifica semanalmente dependências Python e GitHub Actions.
