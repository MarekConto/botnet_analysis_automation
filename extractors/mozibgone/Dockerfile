FROM alpine:latest

WORKDIR /app

COPY . .
RUN apk update && apk add python3 upx

ENTRYPOINT ["python3", "/app/mozibgone.py"]

CMD []

# pouzitie: podman run --rm -v cesta_k_samples:/samples mozibgone <-a/-e> /samples/SAMPLE.elf
# -a = unpack + extract 
# -e = extract