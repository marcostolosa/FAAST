#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FAAST - Módulo de Análise DAST com Nuclei
-----------------------------------------
Este módulo executa testes de segurança dinâmica usando Nuclei
para identificar vulnerabilidades em aplicações web em execução.
"""

import os
import sys
import json
import logging
import tempfile
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger("FAAST.DAST.Nuclei")

# Mapeamento aproximado de severidades Nuclei para CWEs
# Este mapeamento é aproximado e pode precisar de refinamento
NUCLEI_TYPE_TO_CWE = {
    "sql-injection": "CWE-89",
    "xss": "CWE-79",
    "xxe": "CWE-611",
    "ssrf": "CWE-918",
    "open-redirect": "CWE-601",
    "crlf-injection": "CWE-93",
    "lfi": "CWE-22",
    "rfi": "CWE-98",
    "ssti": "CWE-94",
    "csrf": "CWE-352",
    "rce": "CWE-78",
    "file-upload": "CWE-434",
    "default-login": "CWE-798",
    "idor": "CWE-284",
    "jwt": "CWE-347",
    "insecure-deserialization": "CWE-502",
    "cve": "CWE-1026",  # Geral para vulnerabilidades de CVE
    "exposure": "CWE-200",
    "misconfiguration": "CWE-1004",
    "takeover": "CWE-294",
    "default-config": "CWE-16",
    "unauth": "CWE-306",
}

# Mapeamento de severidades Nuclei para formato FAAST
SEVERITY_MAP = {
    "info": "info",
    "low": "low",
    "medium": "medium", 
    "high": "high",
    "critical": "critical"
}


def check_nuclei_installed() -> bool:
    """
    Verifica se o Nuclei está instalado e disponível no PATH.
    
    Returns:
        bool: True se o Nuclei estiver instalado, False caso contrário
    """
    try:
        result = subprocess.run(
            ["nuclei", "-version"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logger.info(f"Nuclei encontrado: {result.stdout.strip()}")
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.error("Nuclei não encontrado. Instale com: https://nuclei.projectdiscovery.io/nuclei/get-started/#nuclei-installation")
        return False


def run_nuclei_scan(
    target_url: str,
    output_file: Optional[str] = None,
    templates: Optional[List[str]] = None,
    severity: Optional[List[str]] = None,
    rate_limit: int = 150,
    timeout: int = 5,
    nuclei_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Executa um scan de segurança usando o Nuclei.
    
    Args:
        target_url: URL completa do alvo a ser testado
        output_file: Arquivo opcional para salvar resultados JSON
        templates: Lista de templates Nuclei específicos para usar
        severity: Lista de severidades a serem testadas (info, low, medium, high, critical)
        rate_limit: Limite de requisições por segundo
        timeout: Timeout para cada template em segundos
        nuclei_path: Caminho opcional para o binário do Nuclei
        
    Returns:
        List[Dict]: Lista de vulnerabilidades encontradas pelo Nuclei
    """
    # Define o caminho do Nuclei
    nuclei_cmd = nuclei_path if nuclei_path else "nuclei"
    
    # Verifica se o Nuclei está instalado
    if not check_nuclei_installed():
        return []
    
    # Cria arquivo temporário para saída JSON se não for fornecido
    if not output_file:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
            output_file = temp_file.name
    
    # Prepara o comando base
    cmd = [
        nuclei_cmd,
        "-target", target_url,
        "-json",
        "-o", output_file,
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout)
    ]
    
    # Adiciona templates específicos se fornecidos
    if templates:
        for template in templates:
            cmd.extend(["-t", template])
    else:
        # Usa templates padrão para aplicações web se não especificado
        cmd.extend(["-t", "cves,vulnerabilities,exposures,misconfigurations"])
    
    # Adiciona severidades específicas se fornecidas
    if severity:
        cmd.extend(["-severity", ",".join(severity)])
    
    # Executa o comando
    logger.info(f"Executando Nuclei contra {target_url}")
    logger.debug(f"Comando: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            check=False,  # Não falhar em saída não-zero
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode != 0:
            logger.warning(f"Nuclei saiu com código {result.returncode}: {result.stderr}")
        
        # Lê o arquivo de saída
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                lines = f.readlines()
                
            # Parse dos resultados linha por linha (o formato é JSONL)
            findings = []
            for line in lines:
                try:
                    finding = json.loads(line)
                    findings.append(finding)
                except json.JSONDecodeError:
                    logger.error(f"Erro ao decodificar linha JSON: {line}")
            
            # Formata os resultados para o formato padrão FAAST
            formatted_findings = _format_nuclei_findings(findings, target_url)
            
            logger.info(f"Nuclei encontrou {len(formatted_findings)} vulnerabilidades")
            return formatted_findings
        else:
            logger.info("Nuclei não encontrou vulnerabilidades")
            return []
            
    except Exception as e:
        logger.error(f"Erro ao executar Nuclei: {e}")
        return []
    
    finally:
        # Se usamos um arquivo temporário, vamos removê-lo
        if not output_file and os.path.exists(output_file):
            os.unlink(output_file)


def _format_nuclei_findings(findings: List[Dict[str, Any]], target_url: str) -> List[Dict[str, Any]]:
    """
    Formata os resultados do Nuclei para o formato padrão FAAST.
    
    Args:
        findings: Lista de vulnerabilidades encontradas pelo Nuclei
        target_url: URL do alvo testado
        
    Returns:
        List[Dict]: Lista de vulnerabilidades formatadas
    """
    formatted_findings = []
    
    for finding in findings:
        # Extrai informações básicas
        template_id = finding.get("template-id", "unknown")
        template_info = finding.get("info", {})
        name = template_info.get("name", "Unknown Vulnerability")
        severity = template_info.get("severity", "info").lower()
        
        # Determina o CWE baseado no tipo de template
        vuln_type = template_id.split("/")[-1].split(".")[0].lower() if "/" in template_id else template_id
        cwe = "CWE-0"
        
        # Busca pelo CWE mais específico possível
        for type_key, cwe_value in NUCLEI_TYPE_TO_CWE.items():
            if type_key in vuln_type or type_key in name.lower():
                cwe = cwe_value
                break
        
        # Extrai dados específicos
        matched_at = finding.get("matched-at", target_url)
        matched_str = finding.get("matched-string", "")
        curl_command = finding.get("curl-command", "")
        
        # Constrói a descrição
        description = template_info.get("description", "")
        
        # Formata o achado no formato FAAST
        formatted_finding = {
            "tool": "nuclei",
            "type": vuln_type,
            "template_id": template_id,
            "rule_id": template_id,
            "name": name,
            "severity": SEVERITY_MAP.get(severity, "info"),
            "message": description,
            "url": matched_at,
            "method": "GET",  # Padrão, pode ser extraído do curl_command se necessário
            "evidence": matched_str,
            "request": curl_command,
            "cwe": cwe,
            "metadata": {
                "confidence": "medium",  # Nuclei não fornece confiança, definimos como média
                "category": "security",
                "tags": template_info.get("tags", []),
                "references": template_info.get("reference", [])
            }
        }
        
        formatted_findings.append(formatted_finding)
    
    return formatted_findings


def run_targeted_nuclei_scan(
    target_url: str,
    vulnerability_type: str,
    params: Optional[List[Dict[str, str]]] = None,
    output_file: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Executa um scan Nuclei direcionado para um tipo específico de vulnerabilidade.
    
    Args:
        target_url: URL completa do alvo a ser testado
        vulnerability_type: Tipo de vulnerabilidade (xss, sqli, etc.)
        params: Lista opcional de parâmetros específicos
        output_file: Arquivo opcional para salvar resultados JSON
        
    Returns:
        List[Dict]: Lista de vulnerabilidades encontradas
    """
    # Mapeia o tipo de vulnerabilidade para templates Nuclei apropriados
    template_map = {
        "xss": ["vulnerabilities/generic/xss-*"],
        "sqli": ["vulnerabilities/generic/sql-injection*", "vulnerabilities/sqlite/sqlite-injection*", "vulnerabilities/mysql/mysql-injection*"],
        "rce": ["vulnerabilities/generic/cmd-injection*", "vulnerabilities/generic/rce*"],
        "ssrf": ["vulnerabilities/generic/ssrf*"],
        "lfi": ["vulnerabilities/generic/lfi*"],
        "idor": ["vulnerabilities/generic/idor*"],
        "csrf": ["vulnerabilities/generic/csrf*"],
        "jwt": ["vulnerabilities/generic/jwt*"],
    }
    
    # Seleciona os templates apropriados
    templates = template_map.get(vulnerability_type.lower(), [])
    
    if not templates:
        logger.warning(f"Tipo de vulnerabilidade não reconhecido: {vulnerability_type}")
        # Usa um template geral para vulnerabilidades
        templates = ["vulnerabilities/generic/"]
    
    # Executa o scan Nuclei
    return run_nuclei_scan(
        target_url=target_url,
        output_file=output_file,
        templates=templates,
        severity=["low", "medium", "high", "critical"]
    )


if __name__ == "__main__":
    """Executa o Nuclei diretamente da linha de comando"""
    import argparse
    
    # Configuração de logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Parse dos argumentos
    parser = argparse.ArgumentParser(description="Análise DAST usando Nuclei")
    parser.add_argument("target", help="URL alvo para análise")
    parser.add_argument("--nuclei-path", help="Caminho para o binário Nuclei (opcional)")
    parser.add_argument("--templates", help="Lista de templates separados por vírgula (opcional)")
    parser.add_argument("--severity", help="Lista de severidades separadas por vírgula (opcional)")
    parser.add_argument("--output", help="Arquivo para salvar resultados JSON")
    args = parser.parse_args()
    
    # Prepara parâmetros
    templates = args.templates.split(",") if args.templates else None
    severity = args.severity.split(",") if args.severity else None
    
    # Executa o Nuclei
    findings = run_nuclei_scan(
        target_url=args.target,
        output_file=args.output,
        templates=templates,
        severity=severity,
        nuclei_path=args.nuclei_path
    )
    
    # Exibe resumo
    print(f"\nNuclei encontrou {len(findings)} vulnerabilidades")
    severities = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        severities[sev] = severities.get(sev, 0) + 1
    
    for sev, count in severities.items():
        print(f"  {sev}: {count}")