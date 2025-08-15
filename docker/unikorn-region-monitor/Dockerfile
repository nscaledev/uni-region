FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.source=https://github.com/nscaledev/uni-region

# This is implcitly created by 'docker buildx build'
ARG TARGETARCH

COPY bin/${TARGETARCH}-linux-gnu/unikorn-region-monitor /

ENTRYPOINT ["/unikorn-region-monitor"]
