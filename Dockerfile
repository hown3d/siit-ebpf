ARG BASE_IMAGE=cgr.dev/chainguard/glibc-dynamic:latest-dev
FROM ${BASE_IMAGE} as base
FROM debian:sid AS deps

ARG TARGETARCH

RUN apt-get update
RUN apt-get install -y clang llvm-dev libbpf-dev linux-headers-generic 
RUN apt-get install -y golang

WORKDIR /work
COPY go.mod go.sum ./
RUN go mod download

FROM deps as builder
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -o manager ./cmd/bpfmanager

FROM base
COPY --from=builder /work/manager /manager
USER root:root
ENTRYPOINT [ "/manager" ]
