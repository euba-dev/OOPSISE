FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Source de données par défaut : base SQLite (données réelles incluses dans l'image)
# Pour basculer sur données fictives : docker run -e DATA_SOURCE=mock ...
ENV DATA_SOURCE=sql
ENV SQL_URL=sqlite:///data/logs.db
ENV SQL_QUERY="SELECT * FROM iptables_logs"

EXPOSE 8501

HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

CMD ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]
