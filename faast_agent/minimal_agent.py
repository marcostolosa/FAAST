#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FAAST Agent - Versão Mínima
---------------------------
Versão simplificada do agente FAAST focando apenas na 
análise SAST e LLM, sem os componentes DAST.
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# LangChain imports (se disponível, caso contrário usa OpenAI diretamente)
try:
    from langchain.chat_models import ChatOpenAI
    from langchain.schema import HumanMessage, SystemMessage
    USE_LANGCHAIN = True
except ImportError:
    import openai
    USE_LANGCHAIN = False

# Local imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from sast.run_semgrep import run_semgrep_analysis
    from sast.run_bandit import run_bandit_analysis
    from utils.cve2capec_mapper import map_cwe_to_capec_attack
except ImportError:
    print("Erro ao importar módulos FAAST. Verifique se o ambiente está corretamente configurado.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("faast.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("FAAST")

# Load environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    logger.error("OPENAI_API_KEY não encontrada. Configure no arquivo .env")
    sys.exit(1)


class FAASTMinimalAgent:
    """
    Versão simplificada do agente FAAST que executa apenas
    análise SAST e usa LLM para analisar resultados.
    """
    
    def __init__(self, target_path: str, output_dir: str = "data/reports"):
        """
        Inicializa o agente FAAST mínimo.
        
        Args:
            target_path: Caminho para o código ou aplicação alvo
            output_dir: Diretório para salvar relatórios
        """
        self.target_path = Path(target_path).absolute()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Resultados da análise
        self.sast_results = []
        self.analyzed_results = []
        
        # Inicializa o modelo LLM
        if USE_LANGCHAIN:
            self.llm = ChatOpenAI(
                model="gpt-4",
                temperature=0.1,
                api_key=OPENAI_API_KEY
            )
        else:
            openai.api_key = OPENAI_API_KEY
        
        logger.info(f"FAAST Agent (versão mínima) inicializado para alvo: {self.target_path}")
    
    def run_pipeline(self) -> Dict[str, Any]:
        """
        Executa o pipeline simplificado do FAAST.
        
        Returns:
            Dict: Resultados da análise
        """
        logger.info("Iniciando pipeline FAAST (versão mínima)")
        
        # Fase 1: Análise SAST
        self._run_sast_analysis()
        
        # Fase 2: Análise LLM dos resultados SAST
        self._analyze_sast_with_llm()
        
        # Fase 3: Enriquecimento com CVE/CAPEC/MITRE
        self._enrich_vulnerabilities()
        
        # Fase 4: Geração de relatórios
        report_path = self._generate_report()
        
        logger.info("Pipeline FAAST (versão mínima) concluído com sucesso")
        return {
            "sast_findings": len(self.sast_results),
            "analyzed_findings": len(self.analyzed_results),
            "report_path": str(report_path)
        }
    
    def _run_sast_analysis(self) -> None:
        """Executa a análise SAST (Semgrep e Bandit)"""
        logger.info("Iniciando análise SAST")
        
        # Executa Semgrep
        try:
            semgrep_results = run_semgrep_analysis(self.target_path)
            logger.info(f"Semgrep encontrou {len(semgrep_results)} problemas potenciais")
            self.sast_results.extend(semgrep_results)
        except Exception as e:
            logger.error(f"Erro ao executar Semgrep: {e}")
        
        # Executa Bandit se o projeto contém Python
        python_files = list(self.target_path.glob("**/*.py"))
        if python_files:
            try:
                bandit_results = run_bandit_analysis(self.target_path)
                logger.info(f"Bandit encontrou {len(bandit_results)} problemas potenciais")
                self.sast_results.extend(bandit_results)
            except Exception as e:
                logger.error(f"Erro ao executar Bandit: {e}")
        
        logger.info(f"Análise SAST concluída. Total: {len(self.sast_results)} achados")
        
        # Se não encontrou nada, adiciona um resultado de teste para debugging
        if not self.sast_results:
            logger.warning("Nenhum resultado SAST encontrado. Adicionando resultado de teste.")
            self.sast_results.append({
                "tool": "test",
                "type": "test_vulnerability",
                "rule_id": "TEST-001",
                "severity": "medium",
                "message": "Este é um resultado de teste para debugging.",
                "file_path": str(self.target_path / "app.py"),
                "line": 1,
                "code": "print('test')",
                "cwe": "CWE-94",
                "metadata": {
                    "confidence": "medium",
                    "category": "test"
                }
            })
    
    def _analyze_sast_with_llm(self) -> None:
        """Analisa os resultados SAST usando o modelo LLM"""
        if not self.sast_results:
            logger.info("Sem resultados SAST para analisar.")
            return
        
        logger.info("Analisando resultados SAST com LLM")
        
        # Formatação dos resultados SAST para o prompt
        sast_findings = json.dumps(self.sast_results, indent=2)
        
        # Sistema prompt para o LLM
        system_prompt = """
        Você é um especialista em segurança de aplicações que está analisando os resultados de ferramentas SAST.
        Sua tarefa é:
        1. Analisar cada resultado e determinar se parece ser um problema real ou falso positivo
        2. Priorizar os problemas em ordem de gravidade (Crítico, Alto, Médio, Baixo)
        3. Para cada problema, explicar o impacto da vulnerabilidade de forma objetiva
        4. Para cada problema, sugerir uma solução ou estratégia de mitigação
        
        Foque em problemas que parecem ser vulnerabilidades exploráveis como:
        - Injeção SQL 
        - XSS (Cross-site scripting)
        - Execução de código remoto
        - SSRF (Server-side request forgery)
        - Acesso inseguro a arquivos
        - Desserialização insegura
        """
        
        # Human prompt com os resultados SAST
        human_prompt = f"""
        Aqui estão os resultados da análise SAST (Semgrep/Bandit) do código:
        
        {sast_findings}
        
        Por favor, analise esses resultados, identifique os problemas mais graves e forneça uma análise 
        detalhada dos problemas encontrados.
        
        Formate sua resposta como um JSON com os campos:
        - analyzed_findings: lista dos problemas analisados com fields (id, severity, is_real_issue, confidence, analysis, impact, remediation)
        """
        
        # Executa a análise via LLM
        if USE_LANGCHAIN:
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=human_prompt)
            ]
            
            response = self.llm(messages)
            response_content = response.content
        else:
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": human_prompt}
                ],
                temperature=0.1
            )
            response_content = response.choices[0].message.content
        
        # Extrai o JSON da resposta
        try:
            # Localiza o JSON na resposta
            json_start = response_content.find('{')
            json_end = response_content.rfind('}') + 1
            json_str = response_content[json_start:json_end]
            
            analysis_result = json.loads(json_str)
            self.analyzed_results = analysis_result.get('analyzed_findings', [])
            logger.info(f"LLM analisou {len(self.analyzed_results)} problemas")
            
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Erro ao processar resposta do LLM: {e}")
            logger.debug(f"Resposta do LLM: {response_content}")
            
            # Armazena a resposta bruta para debugging
            with open(self.output_dir / "llm_response_raw.txt", 'w') as f:
                f.write(response_content)
            
            self.analyzed_results = []
    
    def _enrich_vulnerabilities(self) -> None:
        """Enriquece as vulnerabilidades com mapeamentos CAPEC e MITRE ATT&CK"""
        if not self.analyzed_results:
            logger.info("Sem vulnerabilidades para enriquecer.")
            return
        
        logger.info("Enriquecendo vulnerabilidades com mapeamentos CAPEC e MITRE ATT&CK")
        
        enriched_results = []
        for result in self.analyzed_results:
            # Encontra o resultado SAST original
            original = next((r for r in self.sast_results if r.get('rule_id') == result.get('id')), None)
            
            if not original:
                enriched_results.append(result)
                continue
            
            # Extrai o CWE
            cwe_id = original.get('cwe', 'CWE-0')
            
            try:
                # Mapeia para CAPEC e MITRE ATT&CK
                mappings = map_cwe_to_capec_attack(cwe_id)
                
                # Adiciona os mapeamentos ao resultado
                result['cwe'] = cwe_id
                result['capec'] = mappings.get('capec', [])
                result['mitre_attack'] = mappings.get('mitre_attack', [])
            except Exception as e:
                logger.error(f"Erro ao mapear CWE {cwe_id}: {e}")
            
            enriched_results.append(result)
        
        self.analyzed_results = enriched_results
        logger.info(f"Enriquecimento concluído para {len(self.analyzed_results)} vulnerabilidades")
    
    def _generate_report(self) -> Path:
        """
        Gera um relatório simplificado em formato Markdown.
        
        Returns:
            Path: Caminho para o relatório gerado
        """
        report_path = self.output_dir / "faast_report.md"
        logger.info(f"Gerando relatório em {report_path}")
        
        # Contagens e estatísticas
        total_vulns = len(self.analyzed_results)
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in self.analyzed_results:
            severity = vuln.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Inicia o relatório
        markdown_content = f"""# FAAST: Relatório de Segurança

## Resumo Executivo

**Target:** `{self.target_path}`  
**Data de Execução:** {logging.Formatter.formatTime(logging.Formatter(), logging.LogRecord("", 0, "", 0, None, None, None, None, None))}  
**Total de Vulnerabilidades:** {total_vulns}

### Vulnerabilidades por Severidade

- **Crítico:** {severity_counts['critical']}
- **Alto:** {severity_counts['high']}
- **Médio:** {severity_counts['medium']}
- **Baixo:** {severity_counts['low']}
- **Informativo:** {severity_counts['info']}

## Vulnerabilidades Encontradas

"""
        
        # Mapeamento de severidade para emoji
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵"
        }
        
        # Ordena vulnerabilidades por severidade
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(
            self.analyzed_results, 
            key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5)
        )
        
        # Adiciona cada vulnerabilidade ao relatório
        for i, vuln in enumerate(sorted_vulns, 1):
            severity = vuln.get("severity", "info").lower()
            vuln_id = vuln.get("id", "UNKNOWN-ID")
            is_real = vuln.get("is_real_issue", True)
            emoji = severity_emoji.get(severity, "⚪")
            
            # Título da vulnerabilidade
            vuln_type = vuln_id.split('-')[0] if '-' in vuln_id else vuln_id
            markdown_content += f"### {i}. {emoji} {vuln_type.replace('_', ' ').title()}\n\n"
            
            # Badge para falso positivo
            if not is_real:
                markdown_content += "**[POSSÍVEL FALSO POSITIVO]**\n\n"
            
            # Detalhes básicos
            markdown_content += f"**Severidade:** {severity.title()}  \n"
            markdown_content += f"**ID da Regra:** {vuln_id}  \n"
            markdown_content += f"**Confiança:** {vuln.get('confidence', 'Média')}  \n"
            
            # Adiciona CWE se disponível
            cwe_id = vuln.get('cwe', "")
            if cwe_id:
                cwe_number = cwe_id.replace('CWE-', '')
                markdown_content += f"**CWE:** [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_number}.html)  \n"
            
            # Análise e impacto
            analysis = vuln.get('analysis', "Não disponível")
            impact = vuln.get('impact', "Não disponível")
            remediation = vuln.get('remediation', "Não disponível")
            
            markdown_content += f"\n**Análise:**\n\n{analysis}\n\n"
            markdown_content += f"**Impacto:**\n\n{impact}\n\n"
            markdown_content += f"**Remediação Recomendada:**\n\n{remediation}\n\n"
            
            # Mapeamentos CAPEC e MITRE ATT&CK
            capec_entries = vuln.get('capec', [])
            if capec_entries:
                markdown_content += "**Padrões de Ataque (CAPEC):**\n\n"
                for capec in capec_entries[:3]:  # Limita a 3 para não sobrecarregar
                    capec_id = capec.get('id', '')
                    capec_name = capec.get('name', '')
                    markdown_content += f"- **{capec_id}:** {capec_name}\n"
                    
                    capec_summary = capec.get('summary', '')
                    if capec_summary:
                        summary_preview = capec_summary[:150] + "..." if len(capec_summary) > 150 else capec_summary
                        markdown_content += f"  - {summary_preview}\n"
                
                if len(capec_entries) > 3:
                    markdown_content += f"  - *...e mais {len(capec_entries) - 3} padrões*\n"
                
                markdown_content += "\n"
            
            mitre_entries = vuln.get('mitre_attack', [])
            if mitre_entries:
                markdown_content += "**Técnicas MITRE ATT&CK:**\n\n"
                for technique in mitre_entries[:3]:  # Limita a 3 para não sobrecarregar
                    technique_id = technique.get('id', '')
                    technique_name = technique.get('name', '')
                    technique_tactic = technique.get('tactic', '')
                    technique_url = technique.get('url', '')
                    
                    markdown_content += f"- [{technique_id}: {technique_name}]({technique_url})"
                    if technique_tactic:
                        markdown_content += f" (Tática: {technique_tactic})"
                    markdown_content += "\n"
                
                if len(mitre_entries) > 3:
                    markdown_content += f"- *...e mais {len(mitre_entries) - 3} técnicas*\n"
                
                markdown_content += "\n"
            
            # Linha separadora entre vulnerabilidades
            markdown_content += "---\n\n"
        
        # Adiciona rodapé
        markdown_content += """
## Sobre este Relatório

Este relatório foi gerado automaticamente por **FAAST (Full Agentic Application Security Testing)**, 
uma plataforma que combina análise estática (SAST) e modelos de linguagem grandes (LLMs) para
identificar, analisar e contextualizar vulnerabilidades de segurança.

Para mais informações, visite [https://github.com/yourusername/faast](https://github.com/yourusername/faast)
"""
        
        # Salva o relatório
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        # Salva também o JSON completo para referência
        json_path = self.output_dir / "faast_report.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                "metadata": {
                    "target": str(self.target_path),
                    "execution_date": logging.Formatter.formatTime(logging.Formatter(), logging.LogRecord("", 0, "", 0, None, None, None, None, None)),
                    "faast_version": "0.1.0"
                },
                "summary": {
                    "total_vulnerabilities": total_vulns,
                    "severity_counts": severity_counts
                },
                "vulnerabilities": self.analyzed_results
            }, f, indent=2)
        
        logger.info(f"Relatórios gerados com sucesso em {self.output_dir}")
        return report_path


def main():
    """Função principal para executar o FAAST a partir da linha de comando"""
    parser = argparse.ArgumentParser(description="FAAST: Full Agentic Application Security Testing (Versão Mínima)")
    parser.add_argument("--target", required=True, help="Caminho para o código ou aplicação alvo")
    parser.add_argument("--output", default="data/reports", help="Diretório para salvar relatórios")
    args = parser.parse_args()
    
    # Cria e executa o agente FAAST
    faast_agent = FAASTMinimalAgent(target_path=args.target, output_dir=args.output)
    result = faast_agent.run_pipeline()
    
    # Exibe resumo dos resultados
    print("\n" + "="*50)
    print("FAAST: Análise de Segurança Concluída (Versão Mínima)")
    print("="*50)
    print(f"Achados SAST: {result['sast_findings']}")
    print(f"Vulnerabilidades Analisadas: {result['analyzed_findings']}")
    print(f"Relatório: {result['report_path']}")
    print("="*50)


if __name__ == "__main__":
    main()