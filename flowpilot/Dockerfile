FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# FlowPilot collector binary (invoked as `flowlink`), supplied at build time
# from github.com/alexgoller/flowpilot (Apache-2.0). Until the first release is
# tagged, build it locally and drop the `flowlink` binary into this directory
# before `docker build`. After the first tag, switch this to download the
# pinned release asset (flowpilot-<ver>-x86_64-linux) + verify SHA256SUMS.
COPY flowlink /usr/local/bin/flowlink
RUN chmod +x /usr/local/bin/flowlink

COPY . .

COPY plugin.yaml /.plugger/plugin.yaml
COPY .plugger/metadata.yaml /.plugger/metadata.yaml

EXPOSE 8080
EXPOSE 2055/udp 4739/udp 6343/udp 514/udp
CMD ["python3", "main.py"]
