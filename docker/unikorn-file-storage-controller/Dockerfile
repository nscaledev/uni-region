FROM gcr.io/distroless/static:nonroot

# This is implcitly created by 'docker buildx build'
ARG TARGETARCH

COPY bin/${TARGETARCH}-linux-gnu/unikorn-file-storage-controller /

ENTRYPOINT ["/unikorn-file-storage-controller"]
