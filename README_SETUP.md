# Configuração e Execução do FAAST

Este guia contém instruções detalhadas para configurar e executar o FAAST (Full Agentic Application Security Testing).

## Configuração Rápida

Para configurar rapidamente o FAAST, execute o script de setup:

```bash
python setup_tools.py
```

Este script:
- Verifica a versão do Python
- Instala as dependências Python
- Instala o Semgrep e Bandit para análise SAST
- Verifica se o Nuclei está instalado (para análise DAST)
- Cria os diretórios necessários
- Configura o arquivo .env

## Configuração Manual

Se preferir configurar manualmente, siga estas etapas:

### 1. Ambiente Python

```bash
# Crie e ative um ambiente virtual
python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate

# Instale as dependências
pip install -r requirements.txt

# Instale o FAAST em modo desenvolvimento
pip install -e .
```

### 2. Ferramentas SAST

```bash
# Instale o Semgrep
pip install semgrep

# Instale o Bandit
pip install bandit
```

### 3. Ferramentas DAST (opcional)

Para análise DAST, instale o Nuclei seguindo as instruções em [README_NUCLEI.md](README_NUCLEI.md).

### 4. Configuração do Ambiente

```bash
# Crie os diretórios necessários
mkdir -p data/reports data/mappings

# Configure o arquivo .env com sua chave API OpenAI
cp .env.example .env
# Edite o arquivo .env e adicione sua chave
```

## Execução do FAAST

### Apenas Análise SAST

Para executar apenas a análise estática (sem DAST):

```bash
python -m faast_agent.main --target ./targets/flask_vulnerable_app --sast-only
```

### Análise SAST + DAST

Para executar análise completa (SAST + DAST), primeiro inicie o aplicativo vulnerável:

```bash
# Inicie o aplicativo Flask vulnerável via Docker
docker-compose up -d
```

Depois execute o FAAST:

```bash
python -m faast_agent.main --target ./targets/flask_vulnerable_app --url http://localhost:5000
```

## Visualização dos Relatórios

Os relatórios são gerados na pasta `data/reports/`:

- `faast_report.md`: Relatório em formato Markdown
- `faast_report.json`: Relatório em formato JSON

Se o servidor web estiver rodando, você também pode visualizar os relatórios em:
http://localhost:8000

## Resolução de Problemas

### Problemas Comuns

1. **Erro de API OpenAI**: Se você receber um erro sobre a API do OpenAI, verifique se:
   - A chave API está corretamente configurada no arquivo `.env`
   - A versão da biblioteca OpenAI é compatível (`pip install openai>=1.0.0`)

2. **Erro do Semgrep ou Bandit**: Se as ferramentas SAST não forem encontradas:
   - Execute o script de setup: `python setup_tools.py`
   - Ou instale manualmente: `pip install semgrep bandit`

3. **Problemas com Docker**: Se o ambiente Docker não iniciar:
   - Verifique se o Docker está instalado e em execução
   - Tente reconstruir os containers: `docker-compose build --no-cache`

4. **Erro de Arquivo ou Diretório**: Se houver erro de arquivos não encontrados:
   - Verifique se todos os diretórios necessários foram criados
   - Certifique-se de que está executando o comando do diretório raiz do projeto

## Desenvolvimento Adicional

Para contribuir com o desenvolvimento do FAAST:

1. **Adicionar Novas Ferramentas SAST**:
   - Crie um novo módulo em `sast/`
   - Implemente o wrapper para a ferramenta
   - Integre ao pipeline no arquivo `faast_agent/main.py`

2. **Adicionar Novas Ferramentas DAST**:
   - Crie um novo módulo em `dast/`
   - Implemente o wrapper para a ferramenta
   - Integre ao pipeline no arquivo `faast_agent/main.py`

3. **Melhorar a Análise LLM**:
   - Refine os prompts em `faast_agent/main.py`
   - Adicione novos tipos de análise
   - Melhore a detecção de falsos positivos