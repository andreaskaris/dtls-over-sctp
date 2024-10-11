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
	openssl req -new -x509 -key _output/server.key -out _output/ssl.pem -days 365

.PHONY: deps
deps:
	yum install -y lksctp-tools-dev
