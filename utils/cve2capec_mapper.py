#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FAAST - Utilitário de Mapeamento CVE2CAPEC
------------------------------------------
Este módulo fornece funcionalidades para mapear vulnerabilidades CWE
para padrões de ataque CAPEC e táticas MITRE ATT&CK, integrando-se
com o projeto Galeax/CVE2CAPEC para enriquecer os relatórios.
"""

import os
import sys
import json
import logging
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger("FAAST.Utils.CVE2CAPEC")

# Caminhos para os dados de mapeamento
DEFAULT_DATA_DIR = Path(__file__).parent.parent / "data" / "mappings"
DEFAULT_CWE_CAPEC_FILE = DEFAULT_DATA_DIR / "cwe_capec_mapping.json"
DEFAULT_CAPEC_ATTACK_FILE = DEFAULT_DATA_DIR / "capec_attack_mapping.json"

# URLs para download dos dados mais recentes
CWE_CAPEC_URL = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main/outputs/CWE_to_CAPEC.json"
CAPEC_ATTACK_URL = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main/outputs/CAPEC_to_MITRE_ATTACK.json"


def ensure_mapping_data_exists() -> Tuple[bool, str]:
    """
    Garante que os arquivos de mapeamento existam localmente.
    Baixa dados atualizados se não existirem.
    
    Returns:
        Tuple[bool, str]: (Sucesso, Mensagem de status)
    """
    # Cria diretório de dados se não existir
    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Verifica se os arquivos de mapeamento existem
    files_exist = (
        DEFAULT_CWE_CAPEC_FILE.exists() and
        DEFAULT_CAPEC_ATTACK_FILE.exists()
    )
    
    if files_exist:
        logger.info("Arquivos de mapeamento encontrados localmente")
        return True, "Arquivos de mapeamento existentes"
    
    # Baixa os arquivos se não existirem
    try:
        logger.info("Baixando arquivos de mapeamento atualizados")
        
        # Baixa mapeamento CWE-CAPEC
        response = requests.get(CWE_CAPEC_URL)
        if response.status_code == 200:
            with open(DEFAULT_CWE_CAPEC_FILE, 'w') as f:
                f.write(response.text)
            logger.info(f"Mapeamento CWE-CAPEC baixado para {DEFAULT_CWE_CAPEC_FILE}")
        else:
            logger.error(f"Erro ao baixar mapeamento CWE-CAPEC: {response.status_code}")
            return False, f"Erro ao baixar CWE-CAPEC: {response.status_code}"
        
        # Baixa mapeamento CAPEC-ATT&CK
        response = requests.get(CAPEC_ATTACK_URL)
        if response.status_code == 200:
            with open(DEFAULT_CAPEC_ATTACK_FILE, 'w') as f:
                f.write(response.text)
            logger.info(f"Mapeamento CAPEC-ATT&CK baixado para {DEFAULT_CAPEC_ATTACK_FILE}")
        else:
            logger.error(f"Erro ao baixar mapeamento CAPEC-ATT&CK: {response.status_code}")
            return False, f"Erro ao baixar CAPEC-ATT&CK: {response.status_code}"
        
        return True, "Arquivos de mapeamento baixados com sucesso"
    
    except Exception as e:
        logger.error(f"Exceção ao baixar arquivos de mapeamento: {e}")
        return False, f"Erro ao baixar arquivos: {e}"


def load_mapping_data() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Carrega os dados de mapeamento dos arquivos locais.
    
    Returns:
        Tuple[Dict, Dict]: (Mapeamento CWE-CAPEC, Mapeamento CAPEC-ATT&CK)
    """
    # Garante que os arquivos existam
    success, message = ensure_mapping_data_exists()
    if not success:
        logger.warning(f"Problema com arquivos de mapeamento: {message}")
        return {}, {}
    
    # Carrega mapeamento CWE-CAPEC
    try:
        with open(DEFAULT_CWE_CAPEC_FILE, 'r') as f:
            cwe_capec_mapping = json.load(f)
        logger.debug(f"Mapeamento CWE-CAPEC carregado com {len(cwe_capec_mapping)} entradas")
    except Exception as e:
        logger.error(f"Erro ao carregar mapeamento CWE-CAPEC: {e}")
        cwe_capec_mapping = {}
    
    # Carrega mapeamento CAPEC-ATT&CK
    try:
        with open(DEFAULT_CAPEC_ATTACK_FILE, 'r') as f:
            capec_attack_mapping = json.load(f)
        logger.debug(f"Mapeamento CAPEC-ATT&CK carregado com {len(capec_attack_mapping)} entradas")
    except Exception as e:
        logger.error(f"Erro ao carregar mapeamento CAPEC-ATT&CK: {e}")
        capec_attack_mapping = {}
    
    return cwe_capec_mapping, capec_attack_mapping


def map_cwe_to_capec_attack(
    cwe_id: str,
    cwe_capec_mapping: Optional[Dict[str, Any]] = None,
    capec_attack_mapping: Optional[Dict[str, Any]] = None
) -> Dict[str, List[Dict[str, str]]]:
    """
    Mapeia um CWE para padrões CAPEC e táticas MITRE ATT&CK.
    
    Args:
        cwe_id: ID do CWE (formato "CWE-XXX")
        cwe_capec_mapping: Dicionário de mapeamento CWE-CAPEC (opcional)
        capec_attack_mapping: Dicionário de mapeamento CAPEC-ATT&CK (opcional)
    
    Returns:
        Dict: Dicionário com mapeamentos CAPEC e MITRE ATT&CK
    """
    # Normaliza o formato do CWE
    if not cwe_id.startswith("CWE-"):
        if cwe_id.lower().startswith("cwe-"):
            cwe_id = "CWE-" + cwe_id[4:]
        elif cwe_id.isdigit():
            cwe_id = f"CWE-{cwe_id}"
        else:
            logger.warning(f"Formato de CWE inválido: {cwe_id}")
            return {"capec": [], "mitre_attack": []}
    
    # Carrega mapeamentos se não fornecidos
    if cwe_capec_mapping is None or capec_attack_mapping is None:
        cwe_capec_mapping, capec_attack_mapping = load_mapping_data()
    
    result = {
        "capec": [],
        "mitre_attack": []
    }
    
    # Mapeia CWE para CAPEC
    capec_ids = []
    if cwe_id in cwe_capec_mapping:
        for capec_entry in cwe_capec_mapping[cwe_id]:
            capec_id = capec_entry.get("CAPEC ID")
            if capec_id:
                capec_ids.append(capec_id)
                result["capec"].append({
                    "id": capec_id,
                    "name": capec_entry.get("CAPEC Name", ""),
                    "summary": capec_entry.get("Summary", ""),
                    "likelihood": capec_entry.get("Typical Likelihood of Exploit", ""),
                    "severity": capec_entry.get("Typical Severity", "")
                })
    
    # Mapeia CAPEC para MITRE ATT&CK
    for capec_id in capec_ids:
        # Formata o ID para corresponder ao formato do mapeamento
        formatted_capec_id = f"CAPEC-{capec_id}" if not capec_id.startswith("CAPEC-") else capec_id
        
        if formatted_capec_id in capec_attack_mapping:
            for attack_entry in capec_attack_mapping[formatted_capec_id]:
                technique_id = attack_entry.get("ATT&CK ID")
                if technique_id:
                    result["mitre_attack"].append({
                        "id": technique_id,
                        "name": attack_entry.get("ATT&CK Name", ""),
                        "tactic": attack_entry.get("Tactic", ""),
                        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
                    })
    
    logger.debug(f"CWE {cwe_id} mapeado para {len(result['capec'])} CAPECs e {len(result['mitre_attack'])} técnicas ATT&CK")
    return result


def enrich_vulnerability_with_mappings(
    vulnerability: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Enriquece uma vulnerabilidade com mapeamentos CAPEC e MITRE ATT&CK.
    
    Args:
        vulnerability: Dicionário com dados da vulnerabilidade
        
    Returns:
        Dict: Vulnerabilidade enriquecida com mapeamentos
    """
    # Extrai o CWE da vulnerabilidade
    cwe_id = vulnerability.get("cwe", "")
    if not cwe_id:
        return vulnerability
    
    # Mapeia o CWE para CAPEC e MITRE ATT&CK
    mappings = map_cwe_to_capec_attack(cwe_id)
    
    # Adiciona os mapeamentos à vulnerabilidade
    vulnerability["capec"] = mappings.get("capec", [])
    vulnerability["mitre_attack"] = mappings.get("mitre_attack", [])
    
    return vulnerability


def enrich_vulnerabilities_batch(
    vulnerabilities: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Enriquece um lote de vulnerabilidades com mapeamentos CAPEC e MITRE ATT&CK.
    
    Args:
        vulnerabilities: Lista de vulnerabilidades
        
    Returns:
        List[Dict]: Lista de vulnerabilidades enriquecidas
    """
    # Carrega os mapeamentos uma vez para todo o lote
    cwe_capec_mapping, capec_attack_mapping = load_mapping_data()
    
    enriched_vulnerabilities = []
    for vuln in vulnerabilities:
        # Extrai o CWE da vulnerabilidade
        cwe_id = vuln.get("cwe", "")
        if not cwe_id:
            enriched_vulnerabilities.append(vuln)
            continue
        
        # Mapeia o CWE para CAPEC e MITRE ATT&CK
        mappings = map_cwe_to_capec_attack(
            cwe_id=cwe_id,
            cwe_capec_mapping=cwe_capec_mapping,
            capec_attack_mapping=capec_attack_mapping
        )
        
        # Adiciona os mapeamentos à vulnerabilidade
        vuln_copy = vuln.copy()
        vuln_copy["capec"] = mappings.get("capec", [])
        vuln_copy["mitre_attack"] = mappings.get("mitre_attack", [])
        
        enriched_vulnerabilities.append(vuln_copy)
    
    logger.info(f"Enriquecidas {len(enriched_vulnerabilities)} vulnerabilidades com mapeamentos CAPEC e MITRE ATT&CK")
    return enriched_vulnerabilities


if __name__ == "__main__":
    """
    Executa o mapeador diretamente da linha de comando para teste.
    Uso: python cve2capec_mapper.py CWE-89
    """
    import argparse
    
    # Configuração de logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Parse dos argumentos
    parser = argparse.ArgumentParser(description="Mapeador de CWE para CAPEC e MITRE ATT&CK")
    parser.add_argument("cwe_id", help="ID do CWE a mapear (formato: CWE-XXX)")
    parser.add_argument("--update", action="store_true", help="Força atualização dos dados de mapeamento")
    parser.add_argument("--output", help="Arquivo para salvar resultados JSON")
    args = parser.parse_args()
    
    # Atualiza os dados se solicitado
    if args.update:
        logger.info("Atualizando dados de mapeamento...")
        success, message = ensure_mapping_data_exists()
        if not success:
            logger.error(f"Falha na atualização: {message}")
            sys.exit(1)
    
    # Executa o mapeamento
    mappings = map_cwe_to_capec_attack(args.cwe_id)
    
    # Salva os resultados se solicitado
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(mappings, f, indent=2)
        logger.info(f"Resultados salvos em: {args.output}")
    
    # Exibe resultados
    print(f"\nMapeamentos para {args.cwe_id}:")
    print(f"CAPECs encontrados: {len(mappings.get('capec', []))}")
    for capec in mappings.get("capec", []):
        print(f"  - {capec.get('id')}: {capec.get('name')}")
        print(f"    Severity: {capec.get('severity')}")
        print(f"    Summary: {capec.get('summary')[:100]}..." if len(capec.get('summary', '')) > 100 else f"    Summary: {capec.get('summary')}")
    
    print(f"\nTécnicas MITRE ATT&CK relacionadas: {len(mappings.get('mitre_attack', []))}")
    for technique in mappings.get("mitre_attack", []):
        print(f"  - {technique.get('id')}: {technique.get('name')}")
        print(f"    Tática: {technique.get('tactic')}")
        print(f"    URL: {technique.get('url')}")