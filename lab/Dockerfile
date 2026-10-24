# One image for every lab service: the gate, the egress proxy, the targets and the scripted agent.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY gate ./gate
COPY lab ./lab
RUN pip install --no-cache-dir . \
 && python -c "from pathlib import Path; from lab.scenarios.s1_poisoned_doc import make_docs; make_docs(Path('/data'))"
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
