# Contribuindo para o FAAST

Agradecemos seu interesse em contribuir para o FAAST (Full Agentic Application Security Testing)! Este documento fornece diretrizes para contribuir com o projeto, independentemente do seu nível de experiência.

## Código de Conduta

Este projeto adota o [Contributor Covenant](https://www.contributor-covenant.org/) como código de conduta. Esperamos que todos os participantes sigam estas diretrizes em todas as interações com o projeto.

## Como posso contribuir?

### Reportando Bugs

Bug reports são extremamente valiosos para melhorar o FAAST. Ao reportar bugs, por favor:

1. **Verifique se o bug já não foi reportado** pesquisando nas issues do GitHub.
2. **Use o template de bug report** para fornecer todas as informações necessárias.
3. **Inclua passos detalhados para reproduzir** o problema.
4. **Descreva o comportamento esperado** versus o comportamento observado.
5. **Inclua capturas de tela ou logs** quando relevante.

### Sugerindo Melhorias

Ideias para novas funcionalidades ou melhorias são sempre bem-vindas:

1. **Descreva claramente a melhoria** e por que ela seria útil.
2. **Forneça exemplos de uso** quando possível.
3. **Considere o impacto** na arquitetura e desempenho do projeto.

### Pull Requests

Para contribuir com código:

1. **Fork o repositório** e crie seu branch a partir do `main`.
2. **Instale as dependências de desenvolvimento** usando `pip install -e ".[dev]"`.
3. **Siga o estilo de código** já presente no projeto (PEP 8).
4. **Adicione ou atualize testes** conforme necessário.
5. **Atualize a documentação** para refletir suas mudanças.
6. **Verifique se todos os testes passam** antes de submeter o PR.
7. **Descreva suas mudanças detalhadamente** no PR.

## Fluxo de Desenvolvimento

1. **Issues**: Todas as tarefas devem começar com uma issue.
2. **Branches**: Use o formato `feature/nome-da-funcionalidade` ou `fix/nome-do-bug`.
3. **Commits**: Escreva mensagens de commit claras e descritivas.
4. **Pull Requests**: PRs devem ser revisados por pelo menos um mantenedor.

## Padrões de Código

### Estilo Python

- Siga o [PEP 8](https://www.python.org/dev/peps/pep-0008/).
- Use [type hints](https://www.python.org/dev/peps/pep-0484/) para anotações de tipo.
- Escreva docstrings no formato [Google Style](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings).

### Testes

- Todos os novos recursos devem ter testes unitários.
- Use [pytest](https://docs.pytest.org/) para escrever testes.
- Mantenha a cobertura de código acima de 80%.

### Documentação

- Mantenha a documentação atualizada com suas mudanças.
- Documente claramente funções, classes e métodos públicos.
- Inclua exemplos de uso quando apropriado.

## Áreas Específicas para Contribuição

Estamos especialmente interessados em contribuições nas seguintes áreas:

### Suporte a Linguagens e Frameworks

- Adicionar suporte para novas linguagens de programação
- Integrar com frameworks específicos de segurança
- Criar regras Semgrep personalizadas

### Melhorias no Agente LLM

- Prompts mais eficazes para análise de vulnerabilidades
- Integração com diferentes modelos de LLM
- Otimização de uso de tokens e desempenho

### Validação de Vulnerabilidades

- Métodos avançados para reduzir falsos positivos
- Exploits automatizados para validação
- Ambiente sandbox para testes seguros

### Relatórios e Visualização

- Formatos adicionais de relatório
- Visualizações interativas
- Integrações com ferramentas de gerenciamento de vulnerabilidades

## Primeiros Passos

Não sabe por onde começar? Confira as issues marcadas com `good first issue` para tarefas adequadas para novos contribuidores.

## Ambiente de Desenvolvimento

Para configurar seu ambiente de desenvolvimento:

```bash
# Clone o repositório
git clone https://github.com/marcostolosa/faast.git
cd faast

# Crie e ative um ambiente virtual
python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate

# Instale em modo desenvolvimento
pip install -e ".[dev]"

# Configure variáveis de ambiente
cp .env.example .env
# Edite .env com suas configurações

# Execute os testes
pytest
```

## Contato

Se tiver dúvidas ou precisar de ajuda, você pode:

- Abrir uma issue no GitHub
- Entrar em contato via [marcos.tolosa@owasp.org]
- Participar do [canal do Discord/Slack]

Agradecemos suas contribuições!