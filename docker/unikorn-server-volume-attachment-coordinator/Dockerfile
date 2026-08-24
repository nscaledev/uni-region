FROM gcr.io/distroless/static:nonroot

ARG TARGETARCH

COPY bin/${TARGETARCH}-linux-gnu/unikorn-server-volume-attachment-coordinator /

ENTRYPOINT ["/unikorn-server-volume-attachment-coordinator"]
