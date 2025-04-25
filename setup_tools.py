#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FAAST Setup Script
-----------------
Este script prepara o ambiente para rodar o FAAST, instalando 
todas as ferramentas necessárias.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_step(message):
    """Imprime mensagem de etapa com formatação."""
    print("\n" + "="*80)
    print(f"  {message}")
    print("="*80)

def run_command(command, check=True):
    """
    Executa um comando shell e retorna o resultado.
    
    Args:
        command: Comando a ser executado (lista ou string)
        check: Se deve falhar em caso de erro
        
    Returns:
        Resultado do comando (stdout)
    """
    if isinstance(command, str):
        command_str = command
    else:
        command_str = " ".join(command)
    
    print(f"Executando: {command_str}")
    
    try:
        result = subprocess.run(
            command, 
            check=check, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar comando: {e}")
        print(f"STDERR: {e.stderr}")
        if check:
            sys.exit(1)
        return None

def check_python_version():
    """Verifica se a versão do Python é compatível."""
    print_step("Verificando versão do Python")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print(f"Python 3.9+ é necessário, mas você tem {sys.version}")
        sys.exit(1)
    
    print(f"✅ Python {sys.version} está OK")

def install_python_dependencies():
    """Instala dependências Python via pip."""
    print_step("Instalando dependências Python")
    
    # Atualiza pip
    run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    
    # Instala dependências do requirements.txt
    requirements_path = Path(__file__).parent / "requirements.txt"
    if requirements_path.exists():
        run_command([sys.executable, "-m", "pip", "install", "-r", str(requirements_path)])
    else:
        print(f"⚠️  Arquivo requirements.txt não encontrado em {requirements_path}")
    
    # Instala o FAAST em modo desenvolvimento
    run_command([sys.executable, "-m", "pip", "install", "-e", "."])
    
    print("✅ Dependências Python instaladas")

def install_semgrep():
    """Instala o Semgrep."""
    print_step("Instalando Semgrep")
    
    try:
        # Verifica se o Semgrep já está instalado
        version = run_command(["semgrep", "--version"], check=False)
        if version:
            print(f"✅ Semgrep já está instalado: {version.strip()}")
            return
    except FileNotFoundError:
        pass
    
    # Instala o Semgrep via pip
    run_command([sys.executable, "-m", "pip", "install", "semgrep"])
    
    # Verifica se a instalação foi bem-sucedida
    try:
        version = run_command(["semgrep", "--version"])
        print(f"✅ Semgrep instalado: {version.strip()}")
    except FileNotFoundError:
        print("⚠️  Semgrep não foi instalado corretamente")

def install_bandit():
    """Instala o Bandit."""
    print_step("Instalando Bandit")
    
    try:
        # Verifica se o Bandit já está instalado
        version = run_command(["bandit", "--version"], check=False)
        if version:
            print(f"✅ Bandit já está instalado: {version.strip()}")
            return
    except FileNotFoundError:
        pass
    
    # Instala o Bandit via pip
    run_command([sys.executable, "-m", "pip", "install", "bandit"])
    
    # Verifica se a instalação foi bem-sucedida
    try:
        version = run_command(["bandit", "--version"])
        print(f"✅ Bandit instalado: {version.strip()}")
    except FileNotFoundError:
        print("⚠️  Bandit não foi instalado corretamente")

def check_nuclei():
    """Verifica se o Nuclei está instalado."""
    print_step("Verificando Nuclei")
    
    try:
        # Verifica se o Nuclei já está instalado
        version = run_command(["nuclei", "-version"], check=False)
        if version:
            print(f"✅ Nuclei já está instalado: {version.strip()}")
            return True
    except FileNotFoundError:
        pass
    
    print("\n⚠️  Nuclei não encontrado.")
    print("Nuclei é necessário para análise DAST. Você pode instalá-lo seguindo as instruções em:")
    print("https://nuclei.projectdiscovery.io/nuclei/get-started/#nuclei-installation")
    
    if platform.system() == "Linux":
        print("\nNo Linux você pode instalar com:")
        print("GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
    elif platform.system() == "Darwin":  # macOS
        print("\nNo macOS você pode instalar com:")
        print("brew install nuclei")
    
    return False

def create_directories():
    """Cria diretórios necessários."""
    print_step("Criando diretórios necessários")
    
    directories = [
        "data/reports",
        "data/mappings",
        "data/zap"
    ]
    
    for directory in directories:
        path = Path(__file__).parent / directory
        path.mkdir(parents=True, exist_ok=True)
        print(f"✅ Diretório criado: {path}")

def setup_env_file():
    """Configura o arquivo .env."""
    print_step("Configurando arquivo .env")
    
    env_path = Path(__file__).parent / ".env"
    env_example_path = Path(__file__).parent / ".env.example"
    
    if env_path.exists():
        print(f"✅ Arquivo .env já existe em {env_path}")
        return
    
    if env_example_path.exists():
        # Copia o .env.example para .env
        with open(env_example_path, 'r') as src, open(env_path, 'w') as dst:
            dst.write(src.read())
        
        print(f"✅ Arquivo .env criado em {env_path} (copiado de .env.example)")
        print("⚠️  Lembre-se de editar o arquivo .env e adicionar sua OPENAI_API_KEY")
    else:
        # Cria um .env básico
        with open(env_path, 'w') as f:
            f.write("# FAAST - Variáveis de Ambiente\n\n")
            f.write("# API Key da OpenAI para GPT-4 (obrigatório)\n")
            f.write("OPENAI_API_KEY=sua_chave_api_aqui\n\n")
        
        print(f"✅ Arquivo .env básico criado em {env_path}")
        print("⚠️  Edite o arquivo .env e adicione sua OPENAI_API_KEY")

def main():
    """Função principal do script de setup."""
    print("\nFAAST - Script de Setup")
    print("=======================")
    
    # Verifica requisitos básicos
    check_python_version()
    
    # Instala componentes
    install_python_dependencies()
    install_semgrep()
    install_bandit()
    check_nuclei()
    
    # Configura ambiente
    create_directories()
    setup_env_file()
    
    print("\n" + "="*80)
    print("  🎉 Setup FAAST concluído!")
    print("="*80)
    print("\nVocê pode agora executar o FAAST com:")
    print("  python -m faast_agent.main --target ./targets/flask_vulnerable_app --sast-only")
    print("\nSe tiver o Nuclei instalado e o aplicativo Flask vulnerável em execução:")
    print("  python -m faast_agent.main --target ./targets/flask_vulnerable_app --url http://localhost:5000")
    print("\nBom hacking! 😎\n")

if __name__ == "__main__":
    main()