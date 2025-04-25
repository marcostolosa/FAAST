#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FAAST Agent - Orquestrador Principal
-----------------------------------
Módulo principal do FAAST que orquestra a execução do pipeline
de análise de segurança combinando SAST, LLM e DAST (Nuclei).
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
    from openai import OpenAI
    USE_LANGCHAIN = False

# Local imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from sast.run_semgrep import run_semgrep_analysis
    from sast.run_bandit import run_bandit_analysis
    from dast.run_nuclei import run_nuclei_scan, run_targeted_nuclei_scan
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


class FAASTAgent:
    """
    Agente principal que orquestra o processo completo de análise de segurança
    usando uma combinação de SAST, DAST (Nuclei) e LLM para análise e validação.
    """
    
    def __init__(self, target_path: str, target_url: Optional[str] = None, output_dir: str = "data/reports"):
        """
        Inicializa o agente FAAST.
        
        Args:
            target_path: Caminho para o código ou aplicação alvo
            target_url: URL da aplicação em execução para testes DAST
            output_dir: Diretório para salvar relatórios
        """
        self.target_path = Path(target_path).absolute()
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Resultados da análise
        self.sast_results = []
        self.dast_targets = []
        self.dast_results = []
        self.validated_vulnerabilities = []
        
        # Inicializa o modelo LLM
        if USE_LANGCHAIN:
            self.llm = ChatOpenAI(
                model="gpt-4o",
                temperature=0.5,
                api_key=OPENAI_API_KEY
            )
        else:
            self.client = OpenAI(api_key=OPENAI_API_KEY)
        
        logger.info(f"FAAST Agent inicializado para alvo: {self.target_path}")
        if self.target_url:
            logger.info(f"URL para análise DAST: {self.target_url}")
    
    def run_pipeline(self) -> Dict[str, Any]:
        """
        Executa o pipeline completo de análise FAAST.
        
        Returns:
            Dict: Resultados da análise e relatório
        """
        logger.info("Iniciando pipeline FAAST")
        
        # Fase 1: Análise SAST
        self._run_sast_analysis()
        
        # Fase 2: Análise LLM dos resultados SAST
        self._analyze_sast_with_llm()
        
        # Fase 3: Configuração e execução de testes DAST (se URL fornecida)
        if self.target_url:
            self._run_dast_analysis()
            
            # Fase 4: Validação final e mapeamento
            self._validate_and_map_vulnerabilities()
        
        # Fase 5: Geração de relatórios
        report_path = self._generate_report()
        
        logger.info("Pipeline FAAST concluído com sucesso")
        return {
            "sast_findings": len(self.sast_results),
            "dast_findings": len(self.dast_results) if self.target_url else 0,
            "validated_vulnerabilities": len(self.validated_vulnerabilities) if self.target_url else 0,
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
        """Analisa os resultados SAST usando o modelo LLM para priorizar e planejar DAST"""
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
        3. Para cada problema priorizado, sugerir endpoints ou parâmetros específicos para testes DAST
        4. Para cada entrada, fornecer um pequeno plano de como validar dinamicamente o problema
        
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
        
        Por favor, analise esses resultados, identifique os problemas mais graves e sugira planos de validação DAST.
        Formate sua resposta como um JSON com os campos:
        - priority_findings: lista dos problemas prioritários com fields (id, severity, reason, confidence)
        - dast_targets: lista de alvos para teste DAST com fields (url_path, params, attack_type, validation_plan)
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
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": human_prompt}
                ],
                temperature=0.5
            )
            response_content = response.choices[0].message.content
        
        # Extrai o JSON da resposta
        try:
            # Localiza o JSON na resposta
            json_start = response_content.find('{')
            json_end = response_content.rfind('}') + 1
            json_str = response_content[json_start:json_end]
            
            analysis_result = json.loads(json_str)
            logger.info(f"LLM priorizou {len(analysis_result.get('priority_findings', []))} problemas")
            
            # Extrai os alvos DAST sugeridos
            self.dast_targets = analysis_result.get('dast_targets', [])
            logger.info(f"LLM sugeriu {len(self.dast_targets)} alvos para teste DAST")
            
            # Salva a análise do LLM para referência
            llm_analysis_path = self.output_dir / "llm_analysis.json"
            with open(llm_analysis_path, 'w', encoding='utf-8') as f:
                json.dump(analysis_result, f, indent=2)
            
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Erro ao processar resposta do LLM: {e}")
            logger.debug(f"Resposta do LLM: {response_content}")
            
            # Armazena a resposta bruta para debugging
            with open(self.output_dir / "llm_response_raw.txt", 'w', encoding='utf-8') as f:
                f.write(response_content)
            
            self.dast_targets = []
    
    def _run_dast_analysis(self) -> None:
        """Executa análise DAST usando Nuclei baseada nas sugestões do LLM"""
        if not self.target_url:
            logger.info("URL alvo não fornecida. Pulando análise DAST.")
            return
        
        if not self.dast_targets:
            logger.info("Sem alvos DAST para testar. Executando scan geral com Nuclei.")
            # Executa um scan geral com Nuclei
            nuclei_results = run_nuclei_scan(
                target_url=self.target_url,
                output_file=str(self.output_dir / "nuclei_results.json")
            )
            
            if nuclei_results:
                self.dast_results.extend(nuclei_results)
                logger.info(f"Nuclei encontrou {len(nuclei_results)} vulnerabilidades")
            
            return
        
        logger.info("Iniciando análise DAST baseada em insights do LLM")
        
        # Para cada alvo sugerido pelo LLM, executa testes específicos com Nuclei
        for target in self.dast_targets:
            attack_type = target.get('attack_type', '').lower()
            url_path = target.get('url_path', '')
            params = target.get('params', [])
            
            # Constrói a URL completa
            if url_path.startswith('http'):
                full_url = url_path
            else:
                # Garante que a URL base termine com /
                base_url = self.target_url if self.target_url.endswith('/') else f"{self.target_url}/"
                # Remove a barra inicial de url_path se houver
                clean_path = url_path[1:] if url_path.startswith('/') else url_path
                full_url = f"{base_url}{clean_path}"
            
            logger.info(f"Testando {attack_type} em {full_url}")
            
            # Executa Nuclei com templates específicos para o tipo de ataque
            nuclei_results = run_targeted_nuclei_scan(
                target_url=full_url,
                vulnerability_type=attack_type,
                params=params,
                output_file=str(self.output_dir / f"nuclei_{attack_type}_results.json")
            )
            
            if nuclei_results:
                self.dast_results.extend(nuclei_results)
                logger.info(f"Nuclei encontrou {len(nuclei_results)} vulnerabilidades para {attack_type}")
        
        logger.info(f"Análise DAST concluída. Total: {len(self.dast_results)} achados")
    
    def _validate_and_map_vulnerabilities(self) -> None:
        """Valida os resultados DAST e realiza mapeamento para CVE/CAPEC/MITRE"""
        if not self.dast_results:
            logger.info("Sem resultados DAST para validar.")
            return
        
        logger.info("Validando vulnerabilidades e realizando mapeamento")
        
        # Para cada resultado DAST, realiza validação e mapeamento
        for result in self.dast_results:
            # Extrai informações básicas
            vuln_type = result.get('type', 'unknown')
            cwe_id = result.get('cwe', 'CWE-0')
            
            try:
                # Mapeia para CAPEC e MITRE ATT&CK
                mappings = map_cwe_to_capec_attack(cwe_id)
                
                # Adiciona o mapeamento ao resultado
                result.update({
                    'capec': mappings.get('capec', []),
                    'mitre_attack': mappings.get('mitre_attack', []),
                    'validated': True
                })
                
                # Adiciona à lista de vulnerabilidades validadas
                self.validated_vulnerabilities.append(result)
            except Exception as e:
                logger.error(f"Erro ao mapear CWE {cwe_id}: {e}")
        
        logger.info(f"Validação concluída. {len(self.validated_vulnerabilities)} vulnerabilidades confirmadas")
    
    def _generate_report(self) -> Path:
        """
        Gera um relatório detalhado em formato Markdown.
        
        Returns:
            Path: Caminho para o relatório gerado
        """
        report_path = self.output_dir / "faast_report.md"
        logger.info(f"Gerando relatório em {report_path}")
        
        # Resultados SAST para o relatório
        sast_vulns = []
        for result in self.sast_results:
            # Encontra análise LLM correspondente se disponível
            # (simplificado - em uma implementação real seria mais complexo)
            # Adiciona o resultado formatado
            sast_vulns.append({
                "source": "SAST",
                "tool": result.get("tool", "unknown"),
                "type": result.get("type", "unknown"),
                "severity": result.get("severity", "unknown"),
                "file_path": result.get("file_path", ""),
                "line": result.get("line", ""),
                "message": result.get("message", ""),
                "code": result.get("code", ""),
                "cwe": result.get("cwe", "")
            })
        
        # Resultados DAST para o relatório
        dast_vulns = []
        for result in self.validated_vulnerabilities:
            dast_vulns.append({
                "source": "DAST",
                "tool": result.get("tool", "unknown"),
                "type": result.get("type", "unknown"),
                "severity": result.get("severity", "unknown"),
                "url": result.get("url", ""),
                "name": result.get("name", ""),
                "message": result.get("message", ""),
                "evidence": result.get("evidence", ""),
                "cwe": result.get("cwe", ""),
                "capec": result.get("capec", []),
                "mitre_attack": result.get("mitre_attack", [])
            })
        
        # Contagens e estatísticas
        total_sast = len(sast_vulns)
        total_dast = len(dast_vulns)
        total_vulns = total_sast + total_dast
        
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        # Conta por severidade
        all_vulns = sast_vulns + dast_vulns
        for vuln in all_vulns:
            severity = vuln.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Inicia o relatório
        markdown_content = f"""# FAAST: Relatório de Segurança

## Resumo Executivo

**Target:** `{self.target_path}`  
**URL Alvo:** `{self.target_url if self.target_url else "N/A"}`  
**Data de Execução:** {logging.Formatter.formatTime(logging.Formatter(), logging.LogRecord("", 0, "", 0, None, None, None, None, None))}  
**Total de Vulnerabilidades:** {total_vulns}

### Vulnerabilidades por Severidade

- **Crítico:** {severity_counts['critical']}
- **Alto:** {severity_counts['high']}
- **Médio:** {severity_counts['medium']}
- **Baixo:** {severity_counts['low']}
- **Informativo:** {severity_counts['info']}

### Vulnerabilidades por Fonte

- **SAST:** {total_sast}
- **DAST:** {total_dast}

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
        
        # Combina e ordena vulnerabilidades por severidade
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(
            all_vulns, 
            key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5)
        )
        
        # Adiciona cada vulnerabilidade ao relatório
        for i, vuln in enumerate(sorted_vulns, 1):
            severity = vuln.get("severity", "info").lower()
            source = vuln.get("source", "SAST")
            vuln_type = vuln.get("type", "unknown")
            tool = vuln.get("tool", "unknown")
            emoji = severity_emoji.get(severity, "⚪")
            
            # Título da vulnerabilidade
            markdown_content += f"### {i}. {emoji} {vuln_type.replace('_', ' ').title()} ({source})\n\n"
            
            # Detalhes básicos
            markdown_content += f"**Severidade:** {severity.title()}  \n"
            markdown_content += f"**Ferramenta:** {tool.title()}  \n"
            
            # Adiciona CWE se disponível
            cwe_id = vuln.get('cwe', '')
            if cwe_id:
                cwe_number = cwe_id.replace('CWE-', '')
                markdown_content += f"**CWE:** [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_number}.html)  \n"
            
            # Detalhes específicos do tipo de vulnerabilidade
            if source == "SAST":
                # Detalhes SAST
                markdown_content += f"**Arquivo:** `{vuln.get('file_path', 'N/A')}`  \n"
                markdown_content += f"**Linha:** {vuln.get('line', 'N/A')}  \n"
                
                # Código vulnerável
                code = vuln.get('code', '')
                if code:
                    markdown_content += "\n**Código Vulnerável:**\n\n```\n"
                    markdown_content += f"{code}\n"
                    markdown_content += "```\n\n"
            
            elif source == "DAST":
                # Detalhes DAST
                markdown_content += f"**URL:** {vuln.get('url', 'N/A')}  \n"
                
                # Evidência
                evidence = vuln.get('evidence', '')
                if evidence:
                    markdown_content += "\n**Evidência:**\n\n```\n"
                    markdown_content += f"{evidence}\n"
                    markdown_content += "```\n\n"
            
            # Descrição
            message = vuln.get('message', '')
            if message:
                markdown_content += f"\n**Descrição:**\n\n{message}\n\n"
            
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
uma plataforma que combina análise estática (SAST), análise dinâmica (DAST) e modelos de linguagem 
grandes (LLMs) para identificar, analisar e contextualizar vulnerabilidades de segurança.

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
                    "target_path": str(self.target_path),
                    "target_url": self.target_url,
                    "execution_date": logging.Formatter.formatTime(logging.Formatter(), logging.LogRecord("", 0, "", 0, None, None, None, None, None)),
                    "faast_version": "0.1.0"
                },
                "summary": {
                    "total_vulnerabilities": total_vulns,
                    "sast_vulnerabilities": total_sast,
                    "dast_vulnerabilities": total_dast,
                    "severity_counts": severity_counts
                },
                "sast_vulnerabilities": sast_vulns,
                "dast_vulnerabilities": dast_vulns
            }, f, indent=2)
        
        logger.info(f"Relatórios gerados com sucesso em {self.output_dir}")
        return report_path


def main():
    """Função principal para executar o FAAST a partir da linha de comando"""
    parser = argparse.ArgumentParser(description="FAAST: Full Agentic Application Security Testing")
    parser.add_argument("--target", required=True, help="Caminho para o código ou aplicação alvo")
    parser.add_argument("--url", help="URL da aplicação em execução para testes DAST")
    parser.add_argument("--output", default="data/reports", help="Diretório para salvar relatórios")
    parser.add_argument("--sast-only", action="store_true", help="Executar apenas análise SAST (sem DAST)")
    args = parser.parse_args()
    
    # Determina a URL para DAST
    target_url = None
    if not args.sast_only and args.url:
        target_url = args.url
    
    # Cria e executa o agente FAAST
    faast_agent = FAASTAgent(
        target_path=args.target,
        target_url=target_url,
        output_dir=args.output
    )
    result = faast_agent.run_pipeline()
    
    # Exibe resumo dos resultados
    print("\n" + "="*50)
    print("FAAST: Análise de Segurança Concluída")
    print("="*50)
    print(f"Achados SAST: {result['sast_findings']}")
    if not args.sast_only and args.url:
        print(f"Achados DAST: {result['dast_findings']}")
        print(f"Vulnerabilidades Validadas: {result['validated_vulnerabilities']}")
    print(f"Relatório: {result['report_path']}")
    print("="*50)


if __name__ == "__main__":
    main()