YUM := $(shell command -v yum 2> /dev/null)
ifndef YUM
	YUM := microdnf
endif

.PHONY: build
build:
	gcc -lsctp -o _output/sctp sctp.c
	gcc -lssl -lsctp -lcrypto -o _output/sctp-dtls sctp-dtls.c ssl.c server.c client.c

.PHONY: build-debug
build-debug:
	gcc -g -lsctp -o _output/sctp sctp.c
	gcc -g -lssl -lsctp -lcrypto -o _output/sctp-dtls sctp-dtls.c ssl.c server.c client.c

.PHONY: certs
certs:
	openssl genpkey -algorithm RSA -out _output/ssl.key
	openssl req -new -x509 -key _output/ssl.key -out _output/ssl.pem -days 365

.PHONY: build-deps
build-deps:
	$(YUM) install -y lksctp-tools-dev gcc

.PHONY: build-container-image
build-container-image:
	podman build -t quay.io/akaris/sctp-dtls:latest .

.PHONY: push-container-image
push-container-image:
	podman push quay.io/akaris/sctp-dtls:latest
