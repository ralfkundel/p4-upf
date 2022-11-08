# P4-UPF

This UPF was tested in end-to-end 5G Standalone networks with free5gc (v3.0.6) and multiple gNodeB implementations (OAI, Amarisoft, airspan).

Further reading:
* 2022: "User Plane Hardware Acceleration in Access Networks: Experiences in Offloading Network Functions in Real 5G Deployments" in Proceedings of the 55th Hawaii International Conference on System Sciences: [Paper](https://scholarspace.manoa.hawaii.edu/bitstreams/565ccce0-ac0b-407c-8484-eb17c521fff4/download)


## Building the data plane

The data plane of this project aims on P4-programmable Intel Tofino switches with SDE 9.7.x. Other SDE versions may work but are not tested.

To build the data plane:
1. copy or clone all files of the tofino_dp folder on your Tofino switch.
2. execute the provided p4_build.sh script

```
cd tofino_dp
./p4_build.sh
```

## Building the control plane

The control plane terminates pfcp (5G N4 Interface) on the northbound interface and connects via gRPC to the Tofino SDE on the south bound.
In addition (coming soon), an optional FPGA for QoS can be controlled by the control plane to support per subscriber traffic shaping.

Ensure that a go installation is present before compiling the control plane. 

To build the control plane:


```
cd control_plane
./install_deps.sh
./build.sh
```

Note: the control plane can run on the Tofino switch or on any server which provides management and data plane connectivity to the Tofino.


## Running the UPF

To run the upf, start the SDE driver and the control plane application as follows in parallel:

on the Tofino:

```
cd tofino_dp
./run_switchd.sh
```

on the control plane server:
```
cd control_plane
./run.sh
```

### Configuring the UPF

All parameters are configured in control_plane/config/p4-upf.yaml  (the config file is chosen in the run.sh script)


| parameter: | description: |
|-----------|-------------|
|     logLevel      |       TraceLevel, DebugLevel, InfoLevel, WarnLevel, ErrorLevel, FatalLevel      |
|      N4Interface     |             |
|      - addr     |      N4 IP of the UPF northbound interface (NOT of the SMF)       |
|      - port    |       should be 8805      |
|     tofino_grpc      |             |
|      - addr     |     IP address of Intel SDE gRPC interface        |
|      - port     |      default: 50052       |
|    slowpath_connection       |             |
|     - switch_port       |      parameters of Tofino port (L1/L2/L3) for the slowpath connection on the Tofino. Note: this port must be L2 connected to the sp_ipv4 interface (see next row)       |
|     - sp_ipv4      |      IPv4 address on the slowpath interface (gtp tunnel) on the controller server       |
|    gtpu       |             |
|     - switch_port      |     L1/L2/L3 params of the N3 interface of the UPF.        |
|     - connected_gnb list      |     List of all connected gNodeBs. Note: only used for arp cache preheating (dynamic arp requesting of gNodeB macs is currently not supported)        |
|     dnn_list      |             |
|     - nat_ip      |      next hop IP (e.g. NAT) of N6 interface for transporting upstream packets    |
|     qos_chip      |             |
|     - enable_qos      |      default: false       |
|     - switch_port      |      L1/L2/L3 setting of FPGA QoS port on Tofino      |


## Funding

This project was funded by Deutsche Telekom Technik GmbH as part of the project Dynamic Networks.

## Code Style

This repository uses the
[GitHub Super-Linter](https://github.com/github/super-linter#super-linter) to
check and enforce code style following community standards.
