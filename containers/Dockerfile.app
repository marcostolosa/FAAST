FROM python:3.9-slim

LABEL maintainer="FAAST Project <marcos.tolosa@owasp.org>"
LABEL description="Container para aplicativo Flask vulnerável usado para testes FAAST"

# Define diretório de trabalho
WORKDIR /app

# Instala dependências
COPY targets/flask_vulnerable_app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia código da aplicação
COPY targets/flask_vulnerable_app/ .

# Expõe porta
EXPOSE 5000

# Define variáveis de ambiente
ENV FLASK_APP=app.py
ENV FLASK_ENV=development
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Executa a aplicação com usuário não-privilegiado
RUN adduser --disabled-password --gecos '' appuser
USER appuser

# Inicia a aplicação
CMD ["flask", "run", "--host=0.0.0.0"]