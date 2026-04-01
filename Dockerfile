FROM gcr.io/distroless/cc-debian12:nonroot

COPY binaries/gate-linux-amd64 /gate

EXPOSE 8080 8443 9090

ENTRYPOINT ["/gate"]
