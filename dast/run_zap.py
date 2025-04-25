#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FAAST - Módulo de Análise DAST com OWASP ZAP
-------------------------------------------
Este módulo executa testes de segurança dinâmica usando OWASP ZAP
para identificar vulnerabilidades em aplicações web em execução.
"""

import os
import sys
import json
import time
import logging
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Tente importar a biblioteca Python ZAP API
try:
    from zapv2 import ZAPv2
except ImportError:
    logging.error("Biblioteca ZAP API não encontrada. Instale com: pip install python-owasp-zap-v2.4")
    ZAPv2 = None

logger = logging.getLogger("FAAST.DAST.ZAP")

# Mapeamento de IDs de alerta ZAP para CWEs
# Baseado na documentação ZAP e WASC
ZAP_TO_CWE = {
    "1": "CWE-79",    # Cross Site Scripting (XSS)
    "2": "CWE-89",    # SQL Injection
    "3": "CWE-79",    # Cross Site Scripting (XSS) - Reflected
    "4": "CWE-79",    # Cross Site Scripting (XSS) - Persistent
    "5": "CWE-94",    # Remote File Inclusion
    "6": "CWE-73",    # Path Traversal
    "7": "CWE-352",   # Cross Site Request Forgery
    "9": "CWE-434",   # Remote File Inclusion
    "10": "CWE-22",   # CRLF Injection
    "13": "CWE-200",  # Information Leakage
    "15": "CWE-693",  # Relaxed Security Header
    "16": "CWE-200",  # Cookie No HttpOnly Flag
    "17": "CWE-614",  # Cookie No Secure Flag
    "18": "CWE-693",  # Content Type Missing
    "19": "CWE-693",  # Content Type Options Missing
    "20": "CWE-693",  # X-Frame-Options Header Missing
    "33": "CWE-693",  # Path Traversal
    "40": "CWE-94",   # Command Injection
    "90": "CWE-78",   # LDAP Injection
    "91": "CWE-643",  # XPath Injection
    "93": "CWE-98",   # SSI Injection
    "94": "CWE-94",   # XML Injection
    "95": "CWE-611",  # XXE
    "96": "CWE-643",  # NoSQL Injection
}


def setup_zap_scan(
    zap_path: Optional[str] = None,
    proxy_address: str = "localhost",
    proxy_port: int = 8080
) -> Optional[ZAPv2]:
    """
    Configura e inicializa o OWASP ZAP para análise DAST.
    
    Args:
        zap_path: Caminho opcional para o executável ZAP
        proxy_address: Endereço do proxy ZAP
        proxy_port: Porta do proxy ZAP
    
    Returns:
        ZAPv2: Instância inicializada do cliente ZAP API ou None em caso de erro
    """
    if ZAPv2 is None:
        logger.error("Biblioteca ZAP API não disponível")
        return None
    
    logger.info(f"Configurando conexão com ZAP em {proxy_address}:{proxy_port}")
    
    # Verifica se o ZAP já está em execução
    try:
        # Tenta conectar ao ZAP já em execução
        zap = ZAPv2(proxies={'http': f'http://{proxy_address}:{proxy_port}',
                             'https': f'http://{proxy_address}:{proxy_port}'})
        
        # Verifica se a conexão está funcional
        version = zap.core.version
        logger.info(f"Conectado a instância ZAP existente (versão {version})")
        return zap
    
    except Exception as e:
        logger.warning(f"Não foi possível conectar a uma instância ZAP existente: {e}")
        
        # Se não estiver rodando e o caminho para o ZAP foi fornecido, tenta iniciar
        if zap_path:
            try:
                import subprocess
                
                # Inicia o ZAP em modo daemon
                logger.info(f"Iniciando ZAP a partir de {zap_path}")
                daemon_cmd = [
                    zap_path, 
                    "-daemon",
                    "-port", str(proxy_port),
                    "-host", proxy_address,
                    "-config", "api.disablekey=true"
                ]
                
                proc = subprocess.Popen(
                    daemon_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Aguarda o ZAP iniciar
                logger.info("Aguardando ZAP iniciar...")
                time.sleep(10)  # Espera inicial
                
                # Tenta conectar ao ZAP
                for attempt in range(5):
                    try:
                        zap = ZAPv2(proxies={'http': f'http://{proxy_address}:{proxy_port}',
                                            'https': f'http://{proxy_address}:{proxy_port}'})
                        version = zap.core.version
                        logger.info(f"Tentativa {attempt+1}: ZAP iniciado com sucesso (versão {version})")
                        return zap
                    except Exception as conn_err:
                        logger.warning(f"Tentativa {attempt+1}: ZAP ainda não disponível: {conn_err}")
                        time.sleep(5)  # Espera entre tentativas
                
                logger.error("Não foi possível iniciar o ZAP após várias tentativas")
                return None
                
            except Exception as e:
                logger.error(f"Erro ao iniciar o ZAP: {e}")
                return None
    
    logger.error("Não foi possível conectar ao ZAP e nenhum caminho para iniciar foi fornecido")
    return None


def run_zap_scan(
    zap: ZAPv2,
    target_url: str,
    params: Optional[List[Dict[str, str]]] = None,
    scan_type: str = "active",
    output_file: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Executa um scan de segurança usando o OWASP ZAP.
    
    Args:
        zap: Instância do cliente ZAP API
        target_url: URL completa do alvo a ser testado
        params: Lista opcional de parâmetros para testar (nome, tipo, valor)
        scan_type: Tipo de scan ('active' ou 'passive')
        output_file: Arquivo opcional para salvar resultados JSON
    
    Returns:
        List[Dict]: Lista de vulnerabilidades encontradas pelo ZAP
    """
    if not zap:
        logger.error("Cliente ZAP não inicializado")
        return []
    
    logger.info(f"Iniciando análise {scan_type} do ZAP para {target_url}")
    
    try:
        # Verifica se a URL é acessível
        logger.info(f"Acessando URL alvo: {target_url}")
        zap.urlopen(target_url)
        time.sleep(2)  # Espera para o site carregar
        
        # Configura escopo do scan
        zap.context.new_context("faast_context")
        zap.context.include_in_context("faast_context", target_url + ".*")
        
        # Spider para descobrir URLs
        logger.info("Iniciando spider para mapeamento do alvo")
        scan_id = zap.spider.scan(target_url)
        
        # Acompanha o progresso do spider
        while int(zap.spider.status(scan_id)) < 100:
            logger.info(f"Spider em andamento: {zap.spider.status(scan_id)}%")
            time.sleep(2)
        
        logger.info("Spider concluído")
        
        # Se tiver parâmetros específicos, testa-os
        if params:
            for param in params:
                param_name = param.get("name", "")
                param_value = param.get("value", "")
                param_type = param.get("type", "")
                
                if param_name and param_type:
                    logger.info(f"Testando parâmetro: {param_name} ({param_type})")
                    
                    # Configura o parâmetro para teste
                    if param_type.lower() in ["xss", "sqli", "rce"]:
                        # Configura políticas de scan específicas
                        if param_type.lower() == "xss":
                            policy = "xss-policy"
                            zap.ascan.add_scan_policy(policy)
                            zap.ascan.enable_scanners_by_category(policy, "xss")
                        elif param_type.lower() == "sqli":
                            policy = "sqli-policy"
                            zap.ascan.add_scan_policy(policy)
                            zap.ascan.enable_scanners_by_category(policy, "sql_injection")
                        elif param_type.lower() == "rce":
                            policy = "rce-policy"
                            zap.ascan.add_scan_policy(policy)
                            zap.ascan.enable_scanners_by_category(policy, "remote_file_inclusion")
                            
                        # Executa scan ativo com política específica
                        logger.info(f"Iniciando scan ativo para {param_type}")
                        ascan_id = zap.ascan.scan(
                            target_url,
                            scanpolicyname=policy,
                            contextid=zap.context.context("faast_context")
                        )
                        
                        # Acompanha o progresso do scan ativo
                        while int(zap.ascan.status(ascan_id)) < 100:
                            logger.info(f"Scan ativo em andamento: {zap.ascan.status(ascan_id)}%")
                            time.sleep(5)
                        
                        logger.info(f"Scan ativo para {param_type} concluído")
        
        # Se não houver parâmetros específicos, executa um scan completo
        else:
            # Executa scan ativo completo
            logger.info("Iniciando scan ativo completo")
            ascan_id = zap.ascan.scan(target_url)
            
            # Acompanha o progresso do scan ativo
            while int(zap.ascan.status(ascan_id)) < 100:
                logger.info(f"Scan ativo em andamento: {zap.ascan.status(ascan_id)}%")
                time.sleep(5)
            
            logger.info("Scan ativo concluído")
        
        # Obtém os alertas (vulnerabilidades encontradas)
        alerts = zap.core.alerts(target_url)
        
        # Formata os resultados para o formato padrão FAAST
        formatted_findings = []
        for alert in alerts:
            alert_id = alert.get("pluginId", "0")
            cwe = ZAP_TO_CWE.get(alert_id, "CWE-0")
            
            formatted_finding = {
                "tool": "zap",
                "type": alert.get("name", "unknown"),
                "rule_id": alert_id,
                "severity": alert.get("risk", "low").lower(),
                "message": alert.get("description", ""),
                "url": alert.get("url", ""),
                "method": alert.get("method", ""),
                "param": alert.get("param", ""),
                "evidence": alert.get("evidence", ""),
                "solution": alert.get("solution", ""),
                "cwe": cwe,
                "metadata": {
                    "confidence": alert.get("confidence", "low").lower(),
                    "category": "security"
                }
            }
            formatted_findings.append(formatted_finding)
        
        # Salva os resultados se solicitado
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(formatted_findings, f, indent=2)
            logger.info(f"Resultados ZAP salvos em: {output_file}")
        
        logger.info(f"ZAP encontrou {len(formatted_findings)} vulnerabilidades")
        return formatted_findings
    
    except Exception as e:
        logger.error(f"Erro durante scan ZAP: {e}")
        return []


if __name__ == "__main__":
    """Executa o ZAP diretamente da linha de comando"""
    import argparse
    
    # Configuração de logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Parse dos argumentos
    parser = argparse.ArgumentParser(description="Análise DAST usando OWASP ZAP")
    parser.add_argument("target", help="URL alvo para análise")
    parser.add_argument("--zap-path", help="Caminho para o executável ZAP (opcional)")
    parser.add_argument("--proxy", default="localhost:8080", help="Endereço e porta do proxy ZAP")
    parser.add_argument("--output", help="Arquivo para salvar resultados JSON")
    args = parser.parse_args()
    
    # Extrai endereço e porta do proxy
    proxy_parts = args.proxy.split(':')
    proxy_address = proxy_parts[0]
    proxy_port = int(proxy_parts[1]) if len(proxy_parts) > 1 else 8080
    
    # Configura e executa o ZAP
    zap = setup_zap_scan(
        zap_path=args.zap_path,
        proxy_address=proxy_address,
        proxy_port=proxy_port
    )
    
    if zap:
        findings = run_zap_scan(
            zap=zap,
            target_url=args.target,
            output_file=args.output
        )
        
        # Exibe resumo
        print(f"\nZAP encontrou {len(findings)} vulnerabilidades")
        severities = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            severities[sev] = severities.get(sev, 0) + 1
        
        for sev, count in severities.items():
            print(f"  {sev}: {count}")
    else:
        logger.error("Não foi possível iniciar ou conectar ao ZAP")