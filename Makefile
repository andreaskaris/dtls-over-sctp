.PHONY: build
build:
	gcc -lsctp -o _output/sctp sctp.c
	gcc -lsctp -o _output/sctp-dtls sctp-dtls.c

.PHONY: build-debug
build-debug:
	gcc -g -lsctp -o _output/sctp sctp.c
	gcc -g -lsctp -o _output/sctp-dtls sctp-dtls.c

.PHONY: deps
deps:
	yum install -y lksctp-tools-dev
