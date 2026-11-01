# Como contribuir

1. Abra uma issue descrevendo a mudança ou o problema.
2. Crie uma branch com um nome claro, por exemplo `feat/filtros-chamados`.
3. Mantenha alterações pequenas e com objetivo definido.
4. Adicione ou atualize testes para comportamentos alterados.
5. Execute `pytest` e `ruff check securedesk tests`.
6. Abra um Pull Request explicando o contexto, a solução e como validar.

## Diretrizes

- Não adicione credenciais, arquivos `.env`, bancos locais ou dados pessoais.
- Valide entradas externas e use consultas SQL parametrizadas.
- Não registre conteúdo sensível em logs.
- Documente limitações e evite afirmar que uma proteção é absoluta.
