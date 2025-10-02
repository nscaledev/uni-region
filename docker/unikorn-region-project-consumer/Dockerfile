FROM gcr.io/distroless/static:nonroot

# This is implcitly created by 'docker buildx build'
ARG TARGETARCH

COPY bin/${TARGETARCH}-linux-gnu/unikorn-region-project-consumer /

ENTRYPOINT ["/unikorn-region-project-consumer"]
