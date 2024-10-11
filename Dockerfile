FROM registry.access.redhat.com/ubi9/ubi-minimal as builder
WORKDIR /src
COPY . .
RUN microdnf install -y make
RUN make build-deps
RUN make build

FROM registry.access.redhat.com/ubi9/ubi-minimal
RUN mkdir /entrypoint
COPY --from=builder /src/_output/* /entrypoint
