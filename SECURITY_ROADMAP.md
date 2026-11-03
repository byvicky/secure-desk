# SecureDesk — roteiro de segurança

Status deste roteiro: implementação na branch `test/securedesk-playwright`. O commit de referência atual tem os workflows de qualidade, testes e auditoria de dependências aprovados.

| Prioridade | Item | Situação | Evidência / próximo passo |
|---|---|---|---|
| Alta | Auditoria de PII em campos, respostas da API e logs | 🟡 Parcial | Novos solicitantes, títulos, descrições e comentários passam por redação heurística; respostas 422 não ecoam valores rejeitados; IDs de requisição são gerados pelo servidor. Ainda falta inventário completo de todos os caminhos de dados, padrões de PII e logs de produção. |
| Alta | Tratamento retroativo de dados sensíveis já armazenados | 🟡 Ferramenta pronta; execução pendente | `scripts/audit_pii.py` oferece modo somente leitura e opção `--apply` com backup. É necessário executar primeiro em uma cópia do banco real, revisar contagens e validar o backup antes de qualquer aplicação. |
| Alta | Limites de tamanho e payloads malformados | 🟢 Implementado e validado no CI | Limite padrão de 1 MiB, configurável por `SECUREDESK_MAX_REQUEST_BODY_BYTES`; excesso retorna 413; JSON inválido é rejeitado. |
| Alta | Sessões, expiração, logout e invalidação por permissões | 🟢 Implementado e validado no CI | Cookie com validade máxima de 8 horas; testes controlados verificam expiração, logout e invalidação após desativação ou alteração de papel. Rotas protegidas e `/api/session` consultam o estado atual da conta. CSRF é exigido nas operações de escrita autenticadas por cookie. Não existe fluxo de troca de senha no produto; se for criado, deverá revogar sessões existentes e receber testes próprios. |
| Alta | Exposição de segredos e configurações de produção | 🟡 Revisão parcial | `.env` é ignorado pelo Git e `.env.example` contém somente valores vazios/de demonstração. Falta executar scanner de segredos no histórico completo e revisar configuração real de implantação, que não está disponível neste repositório. |
| Média | Cabeçalhos HTTP e CSP | 🟡 Implementado; revisão contínua | CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` e `Cache-Control` estão ativos; testes verificam os cabeçalhos. Revalidar a CSP ao adicionar recursos externos. |
| Média | SQL injection, XSS e manipulação de parâmetros | 🟡 Cobertura ampliada, não exaustiva | Consultas principais usam parâmetros; filtros têm limites e enums. Foram adicionados testes de payload SQLi e XSS armazenado na interface. Ainda falta fuzzing sistemático de todos os endpoints e parâmetros. |
| Média | Vulnerabilidades em dependências Python e GitHub Actions | 🟢 Automação executada com sucesso no CI | Workflow com `pip-audit`, Dependabot para pip e GitHub Actions e requisito atualizado de setuptools. O workflow Security audit passou no commit de referência. |
| Média | Logs sem tokens, senhas ou PII | 🟡 Parcial | O servidor não confia no ID de requisição enviado pelo cliente, erros de validação não ecoam entradas e os buckets do rate limiter usam HMAC em vez de IPs/usuários em texto puro. Ainda falta revisar logs em ambiente de implantação e testar exceções de cada integração. |
| Média | Rate limiter em cenários de falha e produção | 🟡 Parcial | Falhas SQLite bloqueiam requisições com 503 (fail closed) e há testes automatizados, inclusive concorrência entre processos. SQLite compartilha estado somente entre processos no mesmo host; produção multi-host exige armazenamento distribuído e teste de carga. |

## Evidência de validação

No commit de referência, os workflows abaixo concluíram com sucesso:

- **SecureDesk CI** — qualidade e lint.
- **tests** — testes da API e navegador/Playwright.
- **Security audit** — auditoria de dependências.

A aprovação do CI comprova os testes automatizados executados nesse commit; não equivale a uma auditoria independente nem comprova a segurança de uma implantação em produção.

## Como auditar dados históricos

1. Faça uma cópia consistente do banco SQLite.
2. Execute `python -m scripts.audit_pii --database CAMINHO_DA_COPIA`.
3. Revise as contagens; o script não imprime os valores encontrados.
4. Em uma cópia descartável, teste `--apply` e valide os dados e o arquivo de backup.
5. Só então planeje a execução controlada no banco de destino, com backup externo e janela de manutenção.

A detecção de PII é heurística. Não representa garantia de anonimização nem substitui revisão humana ou uma política formal de retenção e descarte.
