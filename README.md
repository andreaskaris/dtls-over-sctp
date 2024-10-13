# DTLS over SCTP

This is a test implementation of a client/server application sending DTLS encrypted messages via SCTP.

This implementation heavily borrows from the following sources:

*  https://www.educative.io/answers/how-to-implement-udp-sockets-in-c
*  https://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
*  https://github.com/nplab/DTLS-Examples/blob/master/src/dtls_sctp_echo.c

## Deployment on OpenShift

### Prerequisites

The nodes must be configured to load the SCTP module and the pods must set sysctl `net.sctp.auth_enable=1` in their
network namespaces. `net.sctp.auth_enable` is an unsafe sysctl, so it must be allowed by the cluster admin.

First, enable SCTP on the desired nodes:

```
ROLE="worker"
cat <<EOF | oc apply -f -
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: load-sctp-module
  labels:
    machineconfiguration.openshift.io/role: ${ROLE}
spec:
  config:
    ignition:
      version: 3.2.0
    storage:
      files:
        - path: /etc/modprobe.d/sctp-blacklist.conf
          mode: 0644
          overwrite: true
          contents:
            source: data:,
        - path: /etc/modules-load.d/sctp-load.conf
          mode: 0644
          overwrite: true
          contents:
            source: data:,sctp
EOF
```

Now, if the nodes are managed by a `PerformanceProfile`, set the KubeletConfig via `kubeletconfig.experimental`:

```
apiVersion: performance.openshift.io/v2
kind: PerformanceProfile
metadata:
  annotations:
    kubeletconfig.experimental: |
      {"allowedUnsafeSysctls":["net.sctp.auth_enable"]}
  name: performance
spec:
(...)
```

Otherwise, if the nodes are not managed by a `PerformanceProfile`, directly create or modify the already applied
`KubeletConfig`:

```
apiVersion: machineconfiguration.openshift.io/v1
kind: KubeletConfig
metadata:
  name: worker-kubelet-config
spec:
  kubeletConfig:
    allowedUnsafeSysctls:
    - net.sctp.auth_enable
(...)
  machineConfigPoolSelector:
    matchLabels:
      machineconfiguration.openshift.io/role: worker
(...)
```

### Deploying the application

In order to run the application in one pod for the client and one for the server in namespace `sctp-dtls`, execute:

```
make deploy
# make undeploy will remove all resources
```

Result:

```
$ oc get pods
NAME                                READY   STATUS    RESTARTS   AGE
sctp-dtls-client-679b78b988-jhgl9   1/1     Running   0          10m
sctp-dtls-server-5f5b858c85-4mqsp   1/1     Running   0          13m
$ oc logs sctp-dtls-client-679b78b988-jhgl9 --tail=40
NOTIFICATION: sender dry event
+ sleep 1
+ true
+ /entrypoint/sctp-dtls -c -h 10.128.0.151 -p 8080 -m 123456789 -i 10 -k /entrypoint/ssl.key -l /entrypoint/ssl.pem
Socket created successfully
key: /entrypoint/ssl.key
cert: /entrypoint/ssl.pem
Connected with server successfully
NOTIFICATION: sender dry event
------------------------------------------------------------
 countryName               = XX
 localityName              = Default City
 organizationName          = Default Company Ltd

 Cipher: ECDHE-RSA-AES256-GCM-SHA384
------------------------------------------------------------

Sending message: '123456789 (0)'
Server's response: '123456789 (0)'
Sending message: '123456789 (1)'
Server's response: '123456789 (1)'
Sending message: '123456789 (2)'
Server's response: '123456789 (2)'
Sending message: '123456789 (3)'
Server's response: '123456789 (3)'
Sending message: '123456789 (4)'
Server's response: '123456789 (4)'
Sending message: '123456789 (5)'
Server's response: '123456789 (5)'
Sending message: '123456789 (6)'
Server's response: '123456789 (6)'
Sending message: '123456789 (7)'
Server's response: '123456789 (7)'
Sending message: '123456789 (8)'
Server's response: '123456789 (8)'
Sending message: '123456789 (9)'
Server's response: '123456789 (9)'
Cleaning up client connection
NOTIFICATION: sender dry event
+ sleep 1
```

**Note:** The pods' `securityContexts` are configured with `net.sctp.auth_enable=1`:

```
      securityContext:
        sysctls:
        - name: net.sctp.auth_enable
          value: "1"
```

## Building the container image

The container base image uses the UBI 9 base image. The UBI base image needs to pull additional RPMs from Red Hat's
repositories. Therefore, you must build the container image on a registered RHEL 9 or RHEL 8 system. You can then build
and push the image with:

```
make build-container-image IMAGE=<image name>
make push-container-image IMAGE=<image name>
```

## Reading the code

The code for the DTLS over SCTP implementation is in the following files:
```
sctp-dtls.c ssl.c server.c client.c
```

Use `sctp-dtls.c` as an entrypoint and drill down from there.

**Note:** File `sctp.c` contains an implementation that transmits unencoded messages via SCTP only. I left it in this
repository because that's what I started with before adding DTLS with OpenSSL.