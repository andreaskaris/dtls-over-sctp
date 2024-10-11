FROM registry.access.redhat.com/ubi9/ubi-minimal as builder
WORKDIR /src
COPY . .
RUN microdnf install -y make tar gzip
RUN make build-deps
RUN make build
RUN curl -O https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.14.38/openshift-client-linux.tar.gz && tar -xzf openshift-client-linux.tar.gz -C /src/_output

FROM registry.access.redhat.com/ubi9/ubi-minimal
RUN mkdir /entrypoint
RUN microdnf install -y lksctp-tools tar
COPY --from=builder /src/_output/* /entrypoint
