FROM gcr.io/distroless/static:nonroot

# This is implicitly created by 'docker buildx build'.
ARG TARGETARCH

COPY bin/${TARGETARCH}-linux-gnu/unikorn-volume-controller /

ENTRYPOINT ["/unikorn-volume-controller"]
