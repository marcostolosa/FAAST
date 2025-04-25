#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FAAST - Módulo Gerador de Relatórios
------------------------------------
Este módulo gera relatórios detalhados das vulnerabilidades
encontradas pelo FAAST em formatos variados (Markdown, JSON).
"""

import os
import sys
import json
import logging
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger("FAAST.Utils.ReportGenerator")


def generate_markdown_report(
    vulnerabilities: List[Dict[str, Any]],
    target_path: str,
    output_path: Path,
    include_details: bool = True
) -> None:
    """
    Gera um relatório detalhado em formato Markdown.
    
    Args:
        vulnerabilities: Lista de vulnerabilidades encontradas
        target_path: Caminho do alvo analisado
        output_path: Caminho para salvar o relatório
        include_details: Incluir detalhes técnicos completos
    """
    logger.info(f"Gerando relatório Markdown em {output_path}")
    
    # Contagens e estatísticas
    total_vulns = len(vulnerabilities)
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "info").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Data e informações de execução
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Inicia o relatório
    markdown_content = f"""# FAAST: Relatório de Segurança

## Resumo Executivo

**Target:** `{target_path}`  
**Data de Execução:** {current_time}  
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
        vulnerabilities, 
        key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5)
    )
    
    # Adiciona cada vulnerabilidade ao relatório
    for i, vuln in enumerate(sorted_vulns, 1):
        severity = vuln.get("severity", "info").lower()
        tool = vuln.get("tool", "unknown")
        vuln_type = vuln.get("type", "unknown")
        emoji = severity_emoji.get(severity, "⚪")
        
        # Título da vulnerabilidade
        markdown_content += f"### {i}. {emoji} {vuln_type.replace('_', ' ').title()}\n\n"
        
        # Detalhes básicos
        markdown_content += f"**Severidade:** {severity.title()}  \n"
        markdown_content += f"**Ferramenta:** {tool.title()}  \n"
        
        # Adiciona CWE se disponível
        cwe_id = vuln.get("cwe", "")
        if cwe_id:
            markdown_content += f"**CWE:** [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html)  \n"
        
        # Adiciona detalhes baseados no tipo de ferramenta
        if tool == "semgrep" or tool == "bandit":
            # Detalhes SAST
            markdown_content += f"**Arquivo:** `{vuln.get('file_path', 'N/A')}`  \n"
            markdown_content += f"**Linha:** {vuln.get('line', 'N/A')}  \n"
            markdown_content += f"**Regra:** {vuln.get('rule_id', 'N/A')}  \n"
            
            # Código vulnerável
            code = vuln.get('code', '')
            if code and include_details:
                markdown_content += "\n**Código Vulnerável:**\n\n```\n"
                markdown_content += f"{code}\n"
                markdown_content += "```\n\n"
            
        elif tool == "zap":
            # Detalhes ZAP
            markdown_content += f"**URL:** {vuln.get('url', 'N/A')}  \n"
            markdown_content += f"**Método:** {vuln.get('method', 'N/A')}  \n"
            markdown_content += f"**Parâmetro:** {vuln.get('param', 'N/A')}  \n"
            
            # Evidência
            evidence = vuln.get('evidence', '')
            if evidence and include_details:
                markdown_content += "\n**Evidência:**\n\n```\n"
                markdown_content += f"{evidence}\n"
                markdown_content += "```\n\n"
            
        elif tool == "sqlmap":
            # Detalhes SQLMap
            markdown_content += f"**URL:** {vuln.get('url', 'N/A')}  \n"
            markdown_content += f"**Parâmetro:** {vuln.get('param', 'N/A')}  \n"
            markdown_content += f"**Lugar:** {vuln.get('place', 'N/A')}  \n"
            markdown_content += f"**DBMS:** {vuln.get('dbms', 'N/A')}  \n"
            
            # Payload
            payload = vuln.get('payload', '')
            if payload and include_details:
                markdown_content += "\n**Payload:**\n\n```\n"
                markdown_content += f"{payload}\n"
                markdown_content += "```\n\n"
        
        # Descrição e solução
        message = vuln.get('message', '')
        if message:
            markdown_content += f"\n**Descrição:**\n\n{message}\n\n"
        
        solution = vuln.get('solution', '')
        if solution:
            markdown_content += f"**Solução Recomendada:**\n\n{solution}\n\n"
        
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
uma plataforma open-source que combina análise estática (SAST), análise dinâmica (DAST) e validação 
de vulnerabilidades usando modelos de linguagem grandes (LLMs).

Para mais informações, visite [https://github.com/yourusername/faast](https://github.com/yourusername/faast)
"""
    
    # Salva o relatório
    with open(output_path, 'w') as f:
        f.write(markdown_content)
    
    logger.info(f"Relatório Markdown gerado com sucesso em {output_path}")


def generate_json_report(
    vulnerabilities: List[Dict[str, Any]],
    target_path: str,
    output_path: Path
) -> None:
    """
    Gera um relatório detalhado em formato JSON.
    
    Args:
        vulnerabilities: Lista de vulnerabilidades encontradas
        target_path: Caminho do alvo analisado
        output_path: Caminho para salvar o relatório
    """
    logger.info(f"Gerando relatório JSON em {output_path}")
    
    # Contagens e estatísticas
    total_vulns = len(vulnerabilities)
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "info").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Data e informações de execução
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Estrutura do relatório
    report = {
        "metadata": {
            "target": target_path,
            "execution_date": current_time,
            "faast_version": "0.1.0"  # TODO: Obter a versão dinamicamente
        },
        "summary": {
            "total_vulnerabilities": total_vulns,
            "severity_counts": severity_counts
        },
        "vulnerabilities": vulnerabilities
    }
    
    # Salva o relatório
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Relatório JSON gerado com sucesso em {output_path}")


def generate_pdf_report(
    markdown_path: Path,
    output_path: Path
) -> bool:
    """
    Converte um relatório Markdown em PDF.
    
    Args:
        markdown_path: Caminho para o relatório Markdown
        output_path: Caminho para salvar o PDF
        
    Returns:
        bool: True se a conversão foi bem-sucedida, False caso contrário
    """
    logger.info(f"Convertendo relatório Markdown para PDF: {output_path}")
    
    try:
        # Tenta usar o gripho se disponível
        import gripho  # type: ignore
        
        gripho.convert_to_pdf(
            input_file=str(markdown_path),
            output_file=str(output_path)
        )
        logger.info(f"Relatório PDF gerado com sucesso usando gripho")
        return True
    except ImportError:
        logger.warning("Biblioteca gripho não encontrada. Tentando pandoc...")
        
        try:
            # Tenta usar pandoc
            import subprocess
            
            result = subprocess.run([
                "pandoc",
                str(markdown_path),
                "-o", str(output_path),
                "--pdf-engine=xelatex",
                "-V", "geometry:margin=1in"
            ], check=True)
            
            if result.returncode == 0:
                logger.info(f"Relatório PDF gerado com sucesso usando pandoc")
                return True
            else:
                logger.error(f"Erro ao gerar PDF com pandoc")
                return False
                
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Erro ao executar pandoc: {e}")
            logger.warning("Para gerar PDFs, instale gripho (pip install gripho) ou pandoc (https://pandoc.org/installing.html)")
            return False


if __name__ == "__main__":
    """
    Executa o gerador de relatórios diretamente da linha de comando.
    Uso: python report_generator.py vulnerabilities.json target_path output_dir
    """
    import argparse
    
    # Configuração de logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Parse dos argumentos
    parser = argparse.ArgumentParser(description="Gerador de Relatórios FAAST")
    parser.add_argument("vulnerabilities", help="Arquivo JSON com vulnerabilidades")
    parser.add_argument("target", help="Caminho do alvo analisado")
    parser.add_argument("output_dir", help="Diretório para salvar os relatórios")
    parser.add_argument("--no-pdf", action="store_true", help="Não gerar relatório PDF")
    args = parser.parse_args()
    
    # Carrega as vulnerabilidades
    try:
        with open(args.vulnerabilities, 'r') as f:
            vulnerabilities = json.load(f)
    except Exception as e:
        logger.error(f"Erro ao carregar arquivo de vulnerabilidades: {e}")
        sys.exit(1)
    
    # Cria diretório de saída se não existir
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Gera relatórios
    markdown_path = output_dir / "faast_report.md"
    generate_markdown_report(
        vulnerabilities=vulnerabilities,
        target_path=args.target,
        output_path=markdown_path
    )
    
    json_path = output_dir / "faast_report.json"
    generate_json_report(
        vulnerabilities=vulnerabilities,
        target_path=args.target,
        output_path=json_path
    )
    
    # Gera PDF se solicitado
    if not args.no_pdf:
        pdf_path = output_dir / "faast_report.pdf"
        success = generate_pdf_report(
            markdown_path=markdown_path,
            output_path=pdf_path
        )
        
        if success:
            print(f"Relatório PDF gerado com sucesso: {pdf_path}")
        else:
            print("Não foi possível gerar o relatório PDF. Verifique os requisitos.")
    
    print(f"Relatórios gerados com sucesso em {output_dir}")