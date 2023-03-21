# Build the manager binary
FROM golang:1.19 as builder
ARG TARGETOS
ARG TARGETARCH

#ENV GO111MODULE=on
ENV GOPROXY=direct

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

RUN apt-get update && \
    apt-get install -y llvm clang make gcc && \
    apt-get install -y libelf-dev && \
    apt-get install -y zlib1g-dev
# Copy the go source
#COPY main.go main.go
#COPY api/ api/
#COPY controllers/ controllers/

COPY . ./
# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
#RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager main.go
RUN make build-linux

# Build BPF
FROM public.ecr.aws/amazonlinux/amazonlinux:2 as bpfbuilder
WORKDIR /workspace
RUN yum update -y && \
    yum install -y iproute procps-ng && \
    yum install -y llvm clang make gcc && \
    yum install -y coreutils kernel-devel elfutils-libelf-devel zlib-devel bpftool libbpf-devel && \
    yum clean all

COPY Makefile ./
COPY . ./
RUN make build-bpf

COPY . ./

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM public.ecr.aws/amazonlinux/amazonlinux:2
RUN yum update -y && \
    yum install -y iptables iproute jq && \
    yum install -y llvm clang make gcc && \
    yum install -y coreutils kernel-devel elfutils-libelf-devel zlib-devel bpftool libbpf-devel util-linux && \
    yum clean all
WORKDIR /
COPY --from=builder /workspace/manager .
COPY --from=bpfbuilder /workspace/pkg/ebpf/c/oom_kill.elf .
COPY --from=bpfbuilder /workspace/pkg/ebpf/c/conn_track.elf .
COPY --from=bpfbuilder /workspace/pkg/ebpf/c/pid_tracking.elf .
#USER 65532:65532

ENTRYPOINT ["/manager"]
