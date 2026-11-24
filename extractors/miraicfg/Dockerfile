FROM alpine:latest

WORKDIR /app

COPY . .

RUN apk update && \
    apk add --no-cache python3 py3-pip radare2 && \
    pip install --break-system-packages python-magic && \
    pip install --break-system-packages .

ENTRYPOINT ["miraicfg"]
CMD []


# pouzitie: podman run --rm -v cesta_k_samples:/samples miraicfg /samples/SAMPLE.elf
# nefunkcny na vela miraiov ale funguje napr na 80091a5d2912312e797e04bd5eb16290bde71f2f1eda338eb5d7d4788033ab9b.elf