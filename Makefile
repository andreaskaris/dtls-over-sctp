YUM := $(shell command -v yum 2> /dev/null)
ifndef YUM
	YUM := microdnf
endif
PROJECT := sctp-dtls
IMAGE ?= quay.io/akaris/sctp-dtls:latest

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
	$(YUM) install -y lksctp-tools-devel openssl-devel gcc

.PHONY: build-container-image
build-container-image:
	podman build -t $(IMAGE) .

.PHONY: build-container-image-debug
build-container-image-debug:
	podman build -t $(IMAGE) -f Dockerfile.debug .

.PHONY: push-container-image
push-container-image:
	podman push $(IMAGE)

.PHONY: deploy
deploy:
	oc new-project $(PROJECT) || oc project $(PROJECT)
	oc label ns $(PROJECT) security.openshift.io/scc.podSecurityLabelSync="false" --overwrite=true;
	oc label ns $(PROJECT) pod-security.kubernetes.io/enforce=privileged --overwrite=true;
	oc label ns $(PROJECT) pod-security.kubernetes.io/warn=privileged --overwrite=true;
	oc label ns $(PROJECT) pod-security.kubernetes.io/audit=privileged --overwrite=true
	oc create serviceaccount sctp-dtls
	oc adm policy add-scc-to-user privileged -z sctp-dtls
	oc apply -f deployment.yaml

.PHONY: undeploy
undeploy:
	oc project default
	oc delete project $(PROJECT)
