FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# FlowPilot (FlowLink) collector binary — a static linux-amd64 build, supplied
# at build time. Until a FlowPilot release exists (flowcollector "project 3"),
# drop the built `flowlink` binary into this directory before `docker build`.
COPY flowlink /usr/local/bin/flowlink
RUN chmod +x /usr/local/bin/flowlink

COPY . .

COPY plugin.yaml /.plugger/plugin.yaml
COPY .plugger/metadata.yaml /.plugger/metadata.yaml

EXPOSE 8080
EXPOSE 2055/udp 4739/udp 6343/udp 514/udp
CMD ["python3", "main.py"]
