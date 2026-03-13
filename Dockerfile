ARG BASE_IMAGE=cgr.dev/chainguard/glibc-dynamic:latest-dev
FROM ${BASE_IMAGE} as base
FROM golang:1.25 AS deps

ARG TARGETARCH

RUN apt-get update
RUN apt-get install -y clang llvm-dev libbpf-dev linux-headers-generic 

WORKDIR /work
COPY go.mod go.sum ./
RUN go mod download

FROM deps as builder
COPY . .
RUN GOARCH=${TARGETARCH} make build

FROM base
COPY --from=builder /work/manager /manager
USER root:root
ENTRYPOINT [ "/manager" ]
