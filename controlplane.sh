#!/bin/bash

# Exit on error
set -e

echo "Setting up Kubernetes control plane..."

# Function to check if a process is running
is_running() {
    pgrep -f "$1" >/dev/null
}

# Function to check if all components are running
check_running() {
    is_running "kubelet" && \
    is_running "containerd"
}

# Function to kill process if running
stop_process() {
    if is_running "$1"; then
        echo "Stopping $1..."
        sudo pkill -f "$1" || true
        while is_running "$1"; do
            sleep 1
        done
    fi
}

start() {

# Source other scripts
# source ./download.sh
# source ./pki.sh

# Get the host IP address
HOST_IP=$(hostname -I | awk '{print $1}')
POD_CIDR=192.168.0.0/24
SAN=10.10.0.1
SVC_CIDR=10.10.0.0/24
DNS_IP=10.10.0.53

# Configure containerd
sudo tee /etc/containerd/config.toml <<EOF
version = 3

[grpc]
  address = "/run/containerd/containerd.sock"

[plugins.'io.containerd.cri.v1.runtime']
  enable_selinux = false
  enable_unprivileged_ports = true
  enable_unprivileged_icmp = true
  device_ownership_from_security_context = false

[plugins.'io.containerd.cri.v1.images']
  snapshotter = "native"
  disable_snapshot_annotations = true

[plugins.'io.containerd.cri.v1.runtime'.cni]
  bin_dir = "/opt/cni/bin"
  conf_dir = "/etc/cni/net.d"

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
  SystemdCgroup = false
EOF

# Configure kubelet
sudo tee /var/lib/kubelet/config.yaml <<EOF
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: true
  webhook:
    enabled: true
  x509:
    clientCAFile: "/var/lib/kubelet/ca.crt"
authorization:
  mode: AlwaysAllow
clusterDomain: "cluster.local"
resolvConf: "/etc/resolv.conf"
clusterDNS:
  - ${DNS_IP}
runtimeRequestTimeout: "15m"
failSwapOn: false
seccompDefault: true
serverTLSBootstrap: false
containerRuntimeEndpoint: "unix:///run/containerd/containerd.sock"
staticPodPath: "/etc/kubernetes/manifests"
tlsCertFile: /var/lib/kubelet/pki/kubelet.crt
tlsPrivateKeyFile: /var/lib/kubelet/pki/kubelet.key
cgroupDriver: cgroupfs
maxPods: 50
providerID: ""
EOF

    if check_running; then
        echo "Kubernetes components are already running"
        return 0
    fi

    # Generate PKI and kubeconfigs
    echo "Generating PKI and kubeconfigs..."
    bash /Users/andrusik/GitHub/mastering-k8s/pki.sh

# Configure CNI
sudo tee /etc/cni/net.d/10-mynet.conf <<EOF
{
    "cniVersion": "0.3.1",
    "name": "mynet",
    "type": "bridge",
    "bridge": "cni0",
    "isGateway": true,
    "ipMasq": true,
    "ipam": {
        "type": "host-local",
        "subnet": "${POD_CIDR}",
        "routes": [
            { "dst": "0.0.0.0/0" }
        ]
    }
}
EOF


    # Ensure containerd data directory exists with correct permissions
    sudo mkdir -p /var/lib/containerd
    sudo chmod 711 /var/lib/containerd

    if ! is_running "containerd"; then
        echo "Starting containerd..."
        export PATH=$PATH:/opt/cni/bin:kubebuilder/bin
        sudo PATH=$PATH:/opt/cni/bin:/usr/sbin /opt/cni/bin/containerd -c /etc/containerd/config.toml &
    fi

### Create extension-apiserver-authentication ConfigMap
sudo kubebuilder/bin/kubectl -n kube-system create configmap extension-apiserver-authentication \
  --from-file=client-ca-file=/etc/kubernetes/pki/ca.crt \
  --from-file=requestheader-client-ca-file=/etc/kubernetes/pki/ca.crt \
  --dry-run=client -o yaml | kubebuilder/bin/kubectl apply -f -


    # Label the node so static pods with nodeSelector can be scheduled
    NODE_NAME=$(hostname)
    sudo kubebuilder/bin/kubectl label node "$NODE_NAME" node-role.kubernetes.io/master="" --overwrite || true

    # Place static Pod manifests for control plane
    echo "Placing static Pod manifests..."
    sudo mkdir -p /etc/kubernetes/manifests
    sudo cp /Users/andrusik/GitHub/mastering-k8s/manifests/etcd.yaml /etc/kubernetes/manifests/
    sudo cp /Users/andrusik/GitHub/mastering-k8s/manifests/kube-apiserver.yaml /etc/kubernetes/manifests/
    sudo cp /Users/andrusik/GitHub/mastering-k8s/manifests/kube-controller-manager.yaml /etc/kubernetes/manifests/
    sudo cp /Users/andrusik/GitHub/mastering-k8s/manifests/kube-scheduler.yaml /etc/kubernetes/manifests/

 # echo "Applying kubernetes service configuration..."
    sudo iptables-save | tee /tmp/iptables_backup.conf | grep -v '\-A' | sudo iptables-restore
    # Keep pod egress MASQUERADE (or forward rules)
    sudo iptables -t nat -A POSTROUTING -s ${POD_CIDR} ! -d ${POD_CIDR} -j MASQUERADE

    # # Ensure pod traffic is allowed through FORWARD
    sudo iptables -A FORWARD -s ${POD_CIDR} -j ACCEPT
    sudo iptables -A FORWARD -d ${POD_CIDR} -j ACCEPT

## Start kube-proxy
tee /tmp/kube-proxy.conf.yml <<EOF
kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
clientConnection:
  kubeconfig: "/var/lib/kubelet/kubeconfig"
mode: "iptables"
clusterCIDR: "${POD_CIDR}"
EOF
     if ! is_running "kube-proxy"; then
    echo "Starting kube-proxy..."
    sudo kubebuilder/bin/kube-proxy --config=/tmp/kube-proxy.conf.yml --proxy-mode=iptables&
    fi

    # Create required directories with proper permissions
    sudo mkdir -p /var/lib/kubelet/pods
    sudo chmod 750 /var/lib/kubelet/pods
    sudo mkdir -p /var/lib/kubelet/plugins
    sudo chmod 750 /var/lib/kubelet/plugins
    sudo mkdir -p /var/lib/kubelet/plugins_registry
    sudo chmod 750 /var/lib/kubelet/plugins_registry

    echo "Starting kubelet..."
    sudo PATH=$PATH:/opt/cni/bin:/usr/sbin kubebuilder/bin/kubelet \
        --kubeconfig=/var/lib/kubelet/kubeconfig \
        --config=/var/lib/kubelet/config.yaml \
        --root-dir=/var/lib/kubelet \
        --cert-dir=/var/lib/kubelet/pki \
        --hostname-override=$(hostname) \
        --node-ip=$HOST_IP \
        --v=0 &

    echo "Waiting for kubelet and apiserver to become ready..."
    # Wait for kubelet
    for i in {1..30}; do
        if check_running; then
            break
        fi
        echo "Waiting for kubelet..."
        sleep 2
    done
    # Wait for apiserver readiness
    for i in {1..60}; do
        if sudo kubebuilder/bin/kubectl get --raw='/readyz?verbose' >/dev/null 2>&1; then
            echo "kube-apiserver is ready"
            break
        fi
        echo "Waiting for kube-apiserver readiness..."
        sleep 2
    done

    echo "Applying extension-apiserver-authentication ConfigMap..."
    sudo kubebuilder/bin/kubectl -n kube-system create configmap extension-apiserver-authentication \
      --from-file=client-ca-file=/etc/kubernetes/pki/ca.crt \
      --from-file=requestheader-client-ca-file=/etc/kubernetes/pki/ca.crt \
      --dry-run=client -o yaml | sudo kubebuilder/bin/kubectl apply -f -

    echo "Deploying nginx workload..."
    sudo kubebuilder/bin/kubectl apply -f /Users/andrusik/GitHub/mastering-k8s/workloads/nginx-deployment.yaml
}

stop() {
    echo "Stopping Kubernetes components..."
    stop_process "cloud-controller-manager"
    stop_process "gce_metadata_server"
    stop_process "kube-controller-manager"
    stop_process "kubelet"
    stop_process "kube-scheduler"
    stop_process "kube-apiserver"
    stop_process "containerd"
    stop_process "etcd"
    stop_process "kube-proxy"
    echo "All components stopped"
}

cleanup() {
    stop
    echo "Cleaning up..."
    sudo rm -rf ./etcd
    sudo rm -rf /var/lib/kubelet/*
    sudo rm -rf /run/containerd/*
    sudo rm -f /tmp/sa.key /tmp/sa.pub /tmp/token.csv /tmp/ca.key /tmp/ca.crt
    echo "Cleanup complete"
}

case "${1:-}" in    start)
        start
        ;;
    stop)
        stop
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo "Usage: $0 {start|stop|cleanup}"
        exit 1
        ;;
esac
