#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FAAST - Módulo de Análise SAST com Bandit
-----------------------------------------
Este módulo executa análise estática de código Python usando Bandit
para identificar vulnerabilidades específicas para Python.
"""

import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger("FAAST.SAST.Bandit")

# Mapeamento entre IDs Bandit e CWEs
# Baseado na documentação: https://bandit.readthedocs.io/en/latest/plugins/index.html
BANDIT_TO_CWE = {
    "B101": "CWE-703",  # assert_used
    "B102": "CWE-676",  # exec_used
    "B103": "CWE-78",   # set_bad_file_permissions
    "B104": "CWE-676",  # hardcoded_bind_all_interfaces
    "B105": "CWE-276",  # hardcoded_password_string
    "B106": "CWE-259",  # hardcoded_password_funcarg
    "B107": "CWE-259",  # hardcoded_password_default
    "B108": "CWE-22",   # hardcoded_tmp_directory
    "B110": "CWE-20",   # try_except_pass
    "B112": "CWE-676",  # try_except_continue
    "B201": "CWE-78",   # flask_debug_true
    "B301": "CWE-78",   # pickle
    "B302": "CWE-94",   # marshal
    "B303": "CWE-94",   # md5
    "B304": "CWE-327",  # ciphers
    "B305": "CWE-330",  # cipher_modes
    "B306": "CWE-327",  # mktemp_q
    "B307": "CWE-330",  # eval
    "B308": "CWE-94",   # mark_safe
    "B309": "CWE-94",   # httpsconnection
    "B310": "CWE-94",   # urllib_urlopen
    "B311": "CWE-330",  # random
    "B312": "CWE-676",  # telnetlib
    "B313": "CWE-676",  # xml_bad_cElementTree
    "B314": "CWE-676",  # xml_bad_ElementTree
    "B315": "CWE-676",  # xml_bad_expatreader
    "B316": "CWE-676",  # xml_bad_expatbuilder
    "B317": "CWE-676",  # xml_bad_sax
    "B318": "CWE-676",  # xml_bad_minidom
    "B319": "CWE-676",  # xml_bad_pulldom
    "B320": "CWE-676",  # xml_bad_etree
    "B321": "CWE-78",   # ftplib
    "B323": "CWE-676",  # unverified_context
    "B324": "CWE-295",  # hashlib_new_insecure_functions
    "B325": "CWE-327",  # tempnam
    "B401": "CWE-676",  # import_telnetlib
    "B402": "CWE-676",  # import_ftplib
    "B403": "CWE-676",  # import_pickle
    "B404": "CWE-78",   # import_subprocess
    "B405": "CWE-78",   # import_xml_etree
    "B406": "CWE-78",   # import_xml_sax
    "B407": "CWE-78",   # import_xml_expat
    "B408": "CWE-78",   # import_xml_minidom
    "B409": "CWE-78",   # import_xml_pulldom
    "B410": "CWE-78",   # import_lxml
    "B411": "CWE-798",  # import_xmlrpclib
    "B412": "CWE-20",   # import_httpoxy
    "B413": "CWE-20",   # import_pycrypto
    "B501": "CWE-22",   # request_with_no_cert_validation
    "B502": "CWE-89",   # ssl_with_bad_version
    "B503": "CWE-295",  # ssl_with_bad_defaults
    "B504": "CWE-295",  # ssl_with_no_version
    "B505": "CWE-327",  # weak_cryptographic_key
    "B506": "CWE-323",  # yaml_load
    "B507": "CWE-693",  # ssh_no_host_key_verification
    "B601": "CWE-78",   # paramiko_calls
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_with_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B608": "CWE-78",   # hardcoded_sql_expressions
    "B609": "CWE-78",   # linux_commands_wildcard_injection
    "B610": "CWE-78",   # django_extra_used
    "B611": "CWE-78",   # django_rawsql_used
    "B701": "CWE-77",   # jinja2_autoescape_false
    "B702": "CWE-287",  # use_of_mako_templates
    "B703": "CWE-94",   # django_mark_safe
}

# Mapeamento de severidade Bandit para formato FAAST
SEVERITY_MAP = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high"
}


def run_bandit_analysis(
    target_path: Path,
    output_file: Optional[str] = None,
    confidence_level: str = "MEDIUM",
    severity_level: str = "LOW"
) -> List[Dict[str, Any]]:
    """
    Executa análise de código Python usando Bandit.
    
    Args:
        target_path: Caminho para o código Python alvo
        output_file: Arquivo opcional para salvar resultados JSON
        confidence_level: Nível mínimo de confiança (LOW, MEDIUM, HIGH)
        severity_level: Nível mínimo de severidade (LOW, MEDIUM, HIGH)
    
    Returns:
        List[Dict]: Lista de problemas encontrados pelo Bandit
    """
    # Verifica se o Bandit está instalado
    try:
        subprocess.run(["bandit", "--version"], 
                      check=True, 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE)
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.error("Bandit não encontrado. Instale com: pip install bandit")
        return []
    
    # Prepara comando para o Bandit
    bandit_cmd = [
        "bandit",
        "-r",  # recursivo
        "-f", "json",  # formato JSON
        "-c", confidence_level,  # nível de confiança
        "-l", severity_level,  # nível de severidade
        str(target_path)
    ]
    
    logger.info(f"Executando Bandit em: {target_path}")
    
    try:
        # Executa o Bandit
        result = subprocess.run(
            bandit_cmd,
            check=False,  # Não falhar se encontrar problemas
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Analisa a saída JSON
        if result.stdout:
            try:
                bandit_output = json.loads(result.stdout)
                findings = bandit_output.get("results", [])
                
                # Formata os resultados para o formato padrão FAAST
                formatted_findings = []
                for finding in findings:
                    # Extrai CWE do ID do teste
                    test_id = finding.get("test_id", "")
                    cwe = BANDIT_TO_CWE.get(test_id, "CWE-0")
                    
                    formatted_finding = {
                        "tool": "bandit",
                        "type": finding.get("test_name", "unknown"),
                        "rule_id": test_id,
                        "severity": SEVERITY_MAP.get(finding.get("issue_severity", "LOW"), "low"),
                        "message": finding.get("issue_text", ""),
                        "file_path": finding.get("filename", ""),
                        "line": finding.get("line_number", 0),
                        "code": finding.get("code", ""),
                        "cwe": cwe,
                        "metadata": {
                            "confidence": SEVERITY_MAP.get(finding.get("issue_confidence", "LOW"), "low"),
                            "category": "security"
                        }
                    }
                    formatted_findings.append(formatted_finding)
                
                # Salva os resultados se solicitado
                if output_file:
                    with open(output_file, 'w') as f:
                        json.dump(formatted_findings, f, indent=2)
                    logger.info(f"Resultados Bandit salvos em: {output_file}")
                
                logger.info(f"Bandit encontrou {len(formatted_findings)} problemas potenciais")
                return formatted_findings
            
            except json.JSONDecodeError:
                logger.error("Erro ao analisar a saída JSON do Bandit")
                logger.debug(f"Saída: {result.stdout}")
                return []
        
        # Verifica erros
        if result.returncode != 0 and result.stderr and result.returncode != 1:
            # Retorno 1 é normal quando problemas são encontrados
            logger.error(f"Erro ao executar Bandit: {result.stderr}")
            return []
        
        # Se não houver achados
        if result.returncode == 0:
            logger.info("Bandit não encontrou problemas de segurança")
            return []
            
        return []
    
    except Exception as e:
        logger.error(f"Exceção ao executar Bandit: {e}")
        return []


if __name__ == "__main__":
    """Executa o Bandit diretamente da linha de comando"""
    import argparse
    
    # Configuração de logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Parse dos argumentos
    parser = argparse.ArgumentParser(description="Análise SAST para Python usando Bandit")
    parser.add_argument("target", help="Caminho para o código Python alvo")
    parser.add_argument("--confidence", choices=["LOW", "MEDIUM", "HIGH"], 
                        default="MEDIUM", help="Nível mínimo de confiança")
    parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH"], 
                        default="LOW", help="Nível mínimo de severidade")
    parser.add_argument("--output", help="Arquivo para salvar resultados JSON")
    args = parser.parse_args()
    
    # Executa o Bandit
    findings = run_bandit_analysis(
        target_path=Path(args.target),
        output_file=args.output,
        confidence_level=args.confidence,
        severity_level=args.severity
    )
    
    # Exibe resumo
    print(f"\nBandit encontrou {len(findings)} problemas potenciais")
    severities = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        severities[sev] = severities.get(sev, 0) + 1
    
    for sev, count in severities.items():
        print(f"  {sev}: {count}")