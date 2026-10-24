# The gate on its own, for running it next to an agent. The lab has its own image (lab/Dockerfile).
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY gate ./gate
COPY lab ./lab
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 honeycomb \
 && mkdir /state && chown honeycomb /state
USER honeycomb
# Put the policy file in a volume and point --config at it. State lives in /state.
VOLUME ["/state"]
ENTRYPOINT ["honeycomb-gate"]
CMD ["version"]
