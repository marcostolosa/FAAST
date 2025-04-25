#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FAAST - Módulo de Análise DAST com SQLMap
-----------------------------------------
Este módulo executa testes de injeção SQL usando SQLMap
para identificar e explorar vulnerabilidades SQL Injection.
"""

import os
import sys
import json
import logging
import tempfile
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger("FAAST.DAST.SQLMap")

# Mapeamento de riscos SQLMap para severidades FAAST
RISK_MAP = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high"
}


def run_sqlmap_scan(
    target_url: str,
    params: Optional[List[Dict[str, str]]] = None,
    cookies: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    output_file: Optional[str] = None,
    sqlmap_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Executa um scan de injeção SQL usando SQLMap.
    
    Args:
        target_url: URL completa do alvo a ser testado
        params: Lista opcional de parâmetros para testar (nome, tipo, valor)
        cookies: String de cookies opcional
        headers: Dicionário de cabeçalhos HTTP opcionais
        output_file: Arquivo opcional para salvar resultados JSON
        sqlmap_path: Caminho opcional para o SQLMap
    
    Returns:
        List[Dict]: Lista de vulnerabilidades de injeção SQL encontradas
    """
    # Verifica se o SQLMap está instalado
    sqlmap_cmd = sqlmap_path if sqlmap_path else "sqlmap"
    try:
        subprocess.run([sqlmap_cmd, "--version"], 
                      check=True, 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE)
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.error(f"SQLMap não encontrado. Verifique se está instalado e no PATH ou forneça o caminho correto.")
        return []
    
    logger.info(f"Iniciando análise SQLMap para {target_url}")
    
    # Cria arquivo temporário para saída JSON
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
        temp_json = temp_file.name
    
    try:
        # Prepara base do comando SQLMap
        sqlmap_cmd_base = [
            sqlmap_cmd,
            "-u", target_url,
            "--batch",           # Modo não interativo
            "--level=3",         # Nível de teste
            "--risk=2",          # Risco (1-3)
            "--threads=4",       # Threads para acelerar o scan
            "--timeout=30",      # Timeout por requisição
            "--retries=2",       # Número de retentativas
            "--json-output=" + temp_json  # Saída em JSON
        ]
        
        # Adiciona parâmetros específicos se fornecidos
        if params:
            # Filtra apenas parâmetros de injeção SQL
            sqli_params = [p.get("name") for p in params if p.get("type", "").lower() == "sqli"]
            if sqli_params:
                sqlmap_cmd_base.extend(["--param-filter", ",".join(sqli_params)])
        
        # Adiciona cookies se fornecidos
        if cookies:
            sqlmap_cmd_base.extend(["--cookie", cookies])
        
        # Adiciona cabeçalhos se fornecidos
        if headers:
            for header, value in headers.items():
                sqlmap_cmd_base.extend(["--header", f"{header}: {value}"])
        
        # Adiciona opções para testes mais completos
        sqlmap_cmd_base.extend([
            "--technique=BEUSTQ",  # Todas as técnicas
            "--dbms=MySQL,Oracle,PostgreSQL,Microsoft SQL Server,SQLite",  # DBMSs mais comuns
            "--tables",            # Enumerar tabelas
            "--banner",            # Obter banner do banco
            "--identify-waf",      # Identificar WAF/IPS
            "--skip-waf"           # Tentar bypass de WAF
        ])
        
        # Executa o SQLMap
        logger.info("Executando SQLMap com parâmetros otimizados para detecção de SQLi")
        logger.debug(f"Comando completo: {' '.join(sqlmap_cmd_base)}")
        
        result = subprocess.run(
            sqlmap_cmd_base,
            check=False,  # Não falhar mesmo com saída não-zero
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Verifica se o JSON de saída foi gerado
        if os.path.exists(temp_json) and os.path.getsize(temp_json) > 0:
            try:
                with open(temp_json, 'r') as f:
                    sqlmap_output = json.load(f)
                
                # Processa os resultados em formato FAAST
                formatted_findings = _process_sqlmap_results(sqlmap_output, target_url)
                
                # Salva os resultados se solicitado
                if output_file:
                    with open(output_file, 'w') as f:
                        json.dump(formatted_findings, f, indent=2)
                    logger.info(f"Resultados SQLMap salvos em: {output_file}")
                
                logger.info(f"SQLMap encontrou {len(formatted_findings)} vulnerabilidades de injeção SQL")
                return formatted_findings
            
            except json.JSONDecodeError as e:
                logger.error(f"Erro ao analisar a saída JSON do SQLMap: {e}")
                return []
        else:
            # SQLMap não gerou JSON ou não encontrou vulnerabilidades
            logger.info("SQLMap não encontrou vulnerabilidades de injeção SQL")
            return []
    
    except Exception as e:
        logger.error(f"Erro durante scan SQLMap: {e}")
        return []
    
    finally:
        # Limpa o arquivo temporário
        if os.path.exists(temp_json):
            os.unlink(temp_json)


def _process_sqlmap_results(sqlmap_output: Dict[str, Any], target_url: str) -> List[Dict[str, Any]]:
    """
    Processa os resultados do SQLMap para o formato padrão FAAST.
    
    Args:
        sqlmap_output: Saída do SQLMap em formato de dicionário
        target_url: URL alvo testada
    
    Returns:
        List[Dict]: Lista de vulnerabilidades formatadas
    """
    formatted_findings = []
    
    # Verifica se há resultados de injeção
    target_data = sqlmap_output.get("data", [])
    if not target_data:
        return []
    
    # Processa cada URL/parâmetro
    for url, url_data in target_data.items():
        if not url_data:
            continue
        
        for param, param_data in url_data.items():
            if not param_data or not isinstance(param_data, dict):
                continue
            
            # Verifica se o parâmetro é vulnerável
            param_type = param_data.get("type", "")
            place = param_data.get("place", "")
            
            if param_type and param_type != "Heuristic test":
                # Calcula a severidade baseada nos detalhes da vulnerabilidade
                severity = "medium"  # Padrão para SQLi
                
                # Verifica o nível de privilégio obtido
                if param_data.get("dbms_cred", {}).get("privilege", "").lower() == "administrator":
                    severity = "high"
                
                # Extrai detalhes da vulnerabilidade
                dbms = param_data.get("dbms", "Unknown")
                title = f"SQL Injection - {dbms} ({param_type})"
                message = f"O parâmetro '{param}' no '{place}' é vulnerável a injeção SQL do tipo {param_type}."
                
                # Extrai payloads e detalhes técnicos
                payloads = param_data.get("data", {}).get("1", {}).get("payload", "")
                if isinstance(payloads, list):
                    payloads = ", ".join(payloads)
                elif not isinstance(payloads, str):
                    payloads = str(payloads)
                
                # Formata o achado
                finding = {
                    "tool": "sqlmap",
                    "type": "sql_injection",
                    "rule_id": "SQLI-" + dbms.replace(" ", "_"),
                    "severity": severity,
                    "message": message,
                    "url": url,
                    "param": param,
                    "place": place,
                    "payload": payloads,
                    "dbms": dbms,
                    "technique": param_type,
                    "cwe": "CWE-89",  # SQL Injection
                    "metadata": {
                        "confidence": "high",  # SQLMap é bastante preciso
                        "category": "sql_injection"
                    }
                }
                formatted_findings.append(finding)
    
    return formatted_findings


if __name__ == "__main__":
    """Executa o SQLMap diretamente da linha de comando"""
    import argparse
    
    # Configuração de logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Parse dos argumentos
    parser = argparse.ArgumentParser(description="Análise de injeção SQL usando SQLMap")
    parser.add_argument("target", help="URL alvo para análise")
    parser.add_argument("--sqlmap-path", help="Caminho para o executável SQLMap (opcional)")
    parser.add_argument("--cookies", help="Cookies para a requisição")
    parser.add_argument("--param", action="append", help="Parâmetros específicos para testar (pode ser usado múltiplas vezes)")
    parser.add_argument("--output", help="Arquivo para salvar resultados JSON")
    args = parser.parse_args()
    
    # Prepara parâmetros se fornecidos
    params = None
    if args.param:
        params = [{"name": p, "type": "sqli"} for p in args.param]
    
    # Executa o SQLMap
    findings = run_sqlmap_scan(
        target_url=args.target,
        params=params,
        cookies=args.cookies,
        output_file=args.output,
        sqlmap_path=args.sqlmap_path
    )
    
    # Exibe resumo
    print(f"\nSQLMap encontrou {len(findings)} vulnerabilidades de injeção SQL")
    if findings:
        print("\nDetalhes:")
        for i, finding in enumerate(findings, 1):
            print(f"  {i}. Parâmetro: {finding.get('param')}")
            print(f"     Tipo: {finding.get('technique')}")
            print(f"     DBMS: {finding.get('dbms')}")
            print(f"     Payload: {finding.get('payload')[:50]}..." if len(finding.get('payload', '')) > 50 else f"     Payload: {finding.get('payload')}")
            print("")