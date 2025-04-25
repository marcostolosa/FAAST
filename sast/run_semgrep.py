#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FAAST - Módulo de Análise SAST com Semgrep
------------------------------------------
Este módulo executa análise estática de código usando Semgrep
com um conjunto configurável de regras.
"""

import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger("FAAST.SAST.Semgrep")

# Regras Semgrep padrão para diferentes linguagens e categorias
DEFAULT_RULE_PACKS = [
    "p/owasp-top-ten",
    "p/security-audit",
    "p/sql-injection",
    "p/xss",
    "p/jwt",
    "p/insecure-transport",
    "p/command-injection",
    "p/secrets",
]


def run_semgrep_analysis(
    target_path: Path,
    rule_packs: Optional[List[str]] = None,
    output_file: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Executa análise de código usando Semgrep com regras especificadas.
    
    Args:
        target_path: Caminho para o código alvo
        rule_packs: Lista de pacotes de regras Semgrep (default: regras de segurança padrão)
        output_file: Arquivo opcional para salvar resultados JSON
    
    Returns:
        List[Dict]: Lista de problemas encontrados pelo Semgrep
    """
    # Verifica se o Semgrep está instalado
    try:
        subprocess.run(["semgrep", "--version"], 
                      check=True, 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE)
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.error("Semgrep não encontrado. Instale com: pip install semgrep")
        return []
    
    # Usa regras padrão se não especificadas
    if rule_packs is None:
        rule_packs = DEFAULT_RULE_PACKS
    
    # Prepara comandos para o Semgrep
    semgrep_cmd = ["semgrep", 
                   "--json",
                   "--disable-version-check"]
    
    # Adiciona regras
    for rule in rule_packs:
        semgrep_cmd.extend(["--config", rule])
    
    # Adiciona caminho alvo
    semgrep_cmd.append(str(target_path))
    
    logger.info(f"Executando Semgrep com regras: {', '.join(rule_packs)}")
    
    try:
        # Executa o Semgrep
        result = subprocess.run(
            semgrep_cmd,
            check=False,  # Não falhar se encontrar problemas
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Analisa a saída JSON
        if result.stdout:
            try:
                semgrep_output = json.loads(result.stdout)
                findings = semgrep_output.get("results", [])
                
                # Formata os resultados para o formato padrão FAAST
                formatted_findings = []
                for finding in findings:
                    formatted_finding = {
                        "tool": "semgrep",
                        "type": finding.get("check_id", "").split(".")[-1],
                        "rule_id": finding.get("check_id"),
                        "severity": finding.get("extra", {}).get("severity", "unknown"),
                        "message": finding.get("extra", {}).get("message", ""),
                        "file_path": finding.get("path"),
                        "line": finding.get("start", {}).get("line"),
                        "code": finding.get("extra", {}).get("lines", ""),
                        "cwe": _extract_cwe(finding),
                        "metadata": {
                            "confidence": finding.get("extra", {}).get("metadata", {}).get("confidence", "unknown"),
                            "category": finding.get("extra", {}).get("metadata", {}).get("category", "unknown")
                        }
                    }
                    formatted_findings.append(formatted_finding)
                
                # Salva os resultados se solicitado
                if output_file:
                    with open(output_file, 'w') as f:
                        json.dump(formatted_findings, f, indent=2)
                    logger.info(f"Resultados Semgrep salvos em: {output_file}")
                
                logger.info(f"Semgrep encontrou {len(formatted_findings)} problemas potenciais")
                return formatted_findings
            
            except json.JSONDecodeError:
                logger.error("Erro ao analisar a saída JSON do Semgrep")
                logger.debug(f"Saída: {result.stdout}")
                return []
        
        # Verifica erros
        if result.returncode != 0 and result.stderr:
            logger.error(f"Erro ao executar Semgrep: {result.stderr}")
            return []
        
        return []
    
    except Exception as e:
        logger.error(f"Exceção ao executar Semgrep: {e}")
        return []


def _extract_cwe(finding: Dict[str, Any]) -> str:
    """
    Extrai o CWE ID dos metadados do Semgrep.
    
    Args:
        finding: Resultado do Semgrep
        
    Returns:
        str: ID do CWE ou "CWE-0" se não encontrado
    """
    # Tenta extrair o CWE do campo metadata
    metadata = finding.get("extra", {}).get("metadata", {})
    cwe = metadata.get("cwe", "")
    
    # Se CWE não estiver nos metadados, tenta extrair da mensagem ou ID da regra
    if not cwe:
        message = finding.get("extra", {}).get("message", "")
        if "CWE-" in message:
            start = message.find("CWE-")
            end = message.find(" ", start)
            if end == -1:
                end = len(message)
            cwe = message[start:end].strip()
    
    # Se ainda não encontrou, tenta extrair do ID da regra
    if not cwe:
        rule_id = finding.get("check_id", "")
        if "cwe-" in rule_id.lower():
            parts = rule_id.lower().split("cwe-")
            if len(parts) > 1:
                cwe_num = parts[1].split(".")[0].split("-")[0]
                if cwe_num.isdigit():
                    cwe = f"CWE-{cwe_num}"
    
    return cwe if cwe else "CWE-0"


if __name__ == "__main__":
    """Executa o Semgrep diretamente da linha de comando"""
    import argparse
    
    # Configuração de logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Parse dos argumentos
    parser = argparse.ArgumentParser(description="Análise SAST usando Semgrep")
    parser.add_argument("target", help="Caminho para o código alvo")
    parser.add_argument("--rules", nargs="+", help="Pacotes de regras Semgrep")
    parser.add_argument("--output", help="Arquivo para salvar resultados JSON")
    args = parser.parse_args()
    
    # Executa o Semgrep
    findings = run_semgrep_analysis(
        target_path=Path(args.target),
        rule_packs=args.rules,
        output_file=args.output
    )
    
    # Exibe resumo
    print(f"\nSemgrep encontrou {len(findings)} problemas potenciais")
    severities = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        severities[sev] = severities.get(sev, 0) + 1
    
    for sev, count in severities.items():
        print(f"  {sev}: {count}")