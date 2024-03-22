## Asmodeus: eBPF-Based Flow Manager

​	Asmodeus is an eBPF (extended Berkeley Packet Filter) powered flow manager designed for efficient network traffic management. It leverages eBPF traffic control hooks to capture and manage network flows based on various criteria such as TCP, UDP, and other network protocols.



### Requirement

Linux kernel version >= 6.7 (for ebpf traffic control hook)

```bash
# ebpf-dev env config
sudo apt install clang libelf1 libelf-dev zlib1g-dev
git submodule update --init --recursive
# boost env config
sudo apt install libboost-all-dev
```

### Run

```bash
make
# example: ./tc2 eth0
./tc2 [interface_name]
```

