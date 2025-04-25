# Estrutura de Relatório Unificado FAAST

Este documento descreve a estrutura padronizada dos relatórios de segurança gerados pelo FAAST, combinando os resultados de análise SAST, DAST e validação de vulnerabilidades.

## Formato JSON

### Estrutura Geral

```json
{
  "metadata": {
    "version": "0.1.0",
    "timestamp": "2023-09-15T14:30:45Z",
    "target": "/path/to/analyzed/application",
    "scan_duration": 1250,
    "tools": ["semgrep", "bandit", "zap", "sqlmap"]
  },
  "summary": {
    "total_vulnerabilities": 12,
    "severity_counts": {
      "critical": 1,
      "high": 3,
      "medium": 5,
      "low": 2,
      "info": 1
    },
    "tools_findings": {
      "sast": 7,
      "dast": 5,
      "validated": 4
    }
  },
  "vulnerabilities": [
    {
      "id": "FAAST-2023-001",
      "title": "SQL Injection in User Login",
      "type": "sql_injection",
      "severity": "high",
      "confidence": "high",
      "description": "A aplicação executa consultas SQL usando concatenação de strings não sanitizadas provenientes de input do usuário.",
      "details": {
        "tool": "semgrep",
        "rule_id": "sql-injection",
        "location": {
          "file": "app/controllers/auth_controller.py",
          "line": 42,
          "column": 10,
          "code": "cursor.execute(f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\")"
        }
      },
      "validation": {
        "status": "confirmed",
        "tool": "sqlmap",
        "details": {
          "payload": "' OR 1=1--",
          "evidence": "Database contents leaked via error message"
        }
      },
      "classification": {
        "cwe": "CWE-89",
        "capec": [
          {
            "id": "CAPEC-66",
            "name": "SQL Injection",
            "likelihood": "High",
            "severity": "High",
            "summary": "An attacker manipulates SQL statements via user input data to execute commands on the database."
          }
        ],
        "mitre_attack": [
          {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1190"
          }
        ]
      },
      "remediation": {
        "recommendation": "Use consultas parametrizadas ou ORM para evitar injeção SQL",
        "code_example": "cursor.execute(\"SELECT * FROM users WHERE username = ? AND password = ?\", (username, password))",
        "references": [
          "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ],
        "difficulty": "easy"
      }
    }
  ]
}
```

## Formato Markdown

O relatório Markdown é gerado a partir da mesma estrutura de dados, mas formatado para visualização humana. Abaixo está a estrutura do relatório Markdown:

```
# FAAST: Relatório de Segurança

## Resumo Executivo

**Target:** `/path/to/analyzed/application`  
**Data de Execução:** 2023-09-15 14:30:45  
**Total de Vulnerabilidades:** 12

### Vulnerabilidades por Severidade

- **Crítico:** 1 🔴
- **Alto:** 3 🟠
- **Médio:** 5 🟡
- **Baixo:** 2 🟢
- **Informativo:** 1 🔵

## Vulnerabilidades Encontradas

### 1. 🟠 SQL Injection in User Login

**Severidade:** Alta  
**Ferramenta:** Semgrep → SQLMap (Confirmado)  
**CWE:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

**Localização:**  
Arquivo: `app/controllers/auth_controller.py`  
Linha: 42

**Código Vulnerável:**
```python
cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
```

**Descrição:**  
A aplicação executa consultas SQL usando concatenação de strings não sanitizadas provenientes de input do usuário.

**Validação:**  
✅ Confirmado via SQLMap  
Payload: `' OR 1=1--`  
Evidência: Database contents leaked via error message

**Padrões de Ataque (CAPEC):**
- **CAPEC-66:** SQL Injection
  - Likelihood: High
  - Severity: High

**Técnicas MITRE ATT&CK:**
- [T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) (Tática: Initial Access)

**Solução Recomendada:**

Use consultas parametrizadas ou ORM para evitar injeção SQL:

```python
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

**Referências:**
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

---

[...outras vulnerabilidades...]

```

## Campos Obrigatórios vs. Opcionais

### Campos Obrigatórios para Cada Vulnerabilidade:
- ID único
- Título
- Tipo de vulnerabilidade
- Severidade
- Descrição
- Fonte da ferramenta
- Localização (arquivo/URL)
- CWE (quando conhecido)
- Status de validação

### Campos Opcionais (quando disponíveis):
- Evidência de exploração
- Classificações CAPEC e MITRE ATT&CK
- Código de exemplo para correção
- Referências externas
- Detalhes técnicos específicos da ferramenta

## Diretrizes para Relatórios

1. **Priorização**: Vulnerabilidades são sempre ordenadas por severidade, das mais críticas para as menos críticas.

2. **Validação**: Vulnerabilidades confirmadas por testes dinâmicos têm precedência sobre aquelas que são apenas teoricamente possíveis.

3. **Contextualização**: Incluir informações contextuais suficientes para entender o impacto da vulnerabilidade no sistema.

4. **Acessibilidade**: Relatórios devem ser compreensíveis tanto para equipes técnicas quanto para stakeholders de negócio.

5. **Acionabilidade**: Cada vulnerabilidade deve incluir passos claros para remediação.

## Formatos de Saída Suportados

- **JSON**: Para integração com ferramentas de terceiros e processamento automatizado
- **Markdown**: Para visualização humana e documentação
- **PDF**: Para compartilhamento e relatórios formais (gerado a partir do Markdown)
- **HTML**: Para visualização interativa (planejado para versões futuras)

## Integração com Sistemas Externos

Os relatórios FAAST podem ser automaticamente integrados com:

- Sistemas de Issue Tracking (Jira, GitHub Issues)
- Plataformas de Gerenciamento de Vulnerabilidades (DefectDojo)
- Notificações de CI/CD
- Ferramentas de Analytics e Dashboards