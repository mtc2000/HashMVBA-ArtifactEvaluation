> *Faster Hash-based Multi-valued Validated Asynchronous Byzantine Agreement* Accepted by [DSN 2025](https://dsn2025.github.io/cpaccepted.html).

# Implementation of "Faster Hash-based Multi-valued Validated Asynchronous Byzantine Agreement"

This codebase contains a proof-of-concept implementation of the hash-based MVBA in the paper [*Faster Hash-based Multi-valued Validated Asynchronous Byzantine Agreement*](dsn25-paper239.accepted-version.pdf), based on [Dumbo-NG](https://github.com/yylluu/Dumbo_NG).

This codebase also includes PoC implementation of FIN-MVBA in [FIN: Practical Signature-Free Asynchronous Common Subset in Constant Time](https://dl.acm.org/doi/10.1145/3576915.3616633), sMVBA★-BLS and sMVBA★-ECDSA, whose full descriptions can be found in the accepted paper.

## Pre-requisites

We utilize `docker` to prepare an isolated and reusable environment for this codebase.

## Docker setup

When `docker` is installed, one can build the environment in a container image `hmvba-test-env` by the following bash commands.

```{bash}
cd docker
docker compose build
```

Then, one can start running the codebase in `docker`.

```{bash}
cd docker
bash run_docker_compose.sh
```

The running `docker` environment has a `sshd` service binding the port `20022` on the `localhost`. Access the docker via SSH with the default username `root` without password.

```{bash}
ssh -p 20022 root@localhost
```

## Non-docker setup

If you do wish to continue on a non-isolated environment, please consult [docker/env.Dockerfile](docker/env.Dockerfile) to understand how dependencies should be installed.

## How to run local tests

Once a working test environment is ready, one can run local experiments via four available `bash` scripts. For advanced usages, please refer to the comments in these scripts.

```
test_hmvba.sh               # test our hash-based MVBA
test_dumbomvbastar.sh       # test sMVBA★-ECDSA
test_dumbomvbastar_bls.sh   # test sMVBA★-BLS
test_finmvba.sh             # test FIN-MVBA
```

Upon completion of a test, logging files will be generated at `log/` and `verbose_log/` folder. 
Files under `log/` record timing information that were manually processed. 
`verbose_log/*.stdout.log` contains self-explanatory statistics for each node. For example, 
```{text}
node: 0 epoch: 1 run: 0.217375, total delivered Txs after warm-up: 10, latency after warm-up: 0.217375, tps after warm-up: 46.003391, average latency by rounds + stddev: 0.217375 0.000000, average tps by rounds + stddev: 46.003391 0.000000, 
```

## Limitations

- Scripts that automate cloud-based experiments on AWS are not provided. We adapted and customized the cloud testing framework in https://zenodo.org/doi/10.5281/zenodo.12736462.
- Due to limitation of computation resources, the results in the original paper cannot be reproduced locally.

---

Here down below is the original README.md of [Dumbo-NG](https://github.com/yylluu/Dumbo_NG).

Proof-of-Concept implementation for Dumbo-NG. 
The code is forked from the implementation of Honeybadger-BFT protocol.
This codebase also includes PoC implementations for Dumbo, sDumbo, Dumbo-DL.

1. To run the benchmarks at your machine (with Ubuntu 18.84 LTS), first install all dependencies as follows:
    ```
    sudo apt-get update
    sudo apt-get -y install make bison flex libgmp-dev libmpc-dev python3 python3-dev python3-pip libssl-dev
    
    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
    tar -xvf pbc-0.5.14.tar.gz
    cd pbc-0.5.14
    sudo ./configure
    sudo make
    sudo make install
    cd ..
    
    sudo ldconfig /usr/local/lib
    
    cat <<EOF >/home/ubuntu/.profile
    export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    EOF
    
    source /home/ubuntu/.profile
    export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
     
    git clone https://github.com/JHUISI/charm.git
    cd charm
    sudo ./configure.sh
    sudo make
    sudo make install
    sudo make test
    cd ..
    
    python3 -m pip install --upgrade pip
    sudo pip3 install gevent setuptools gevent numpy ecdsa pysocks gmpy2 zfec gipc pycrypto coincurve
    ```

2. A quick start to run Dumbo/sDumbo for 20 epochs with a batch size of 1000 tx can be:
   ```
   ./run_local_network_test.sh 4 1 1000 20
   ```
   
   To run Dumbo-NG, replace line 12 of run_local_network_test.sh with:
   ```
   python3 run_socket_node.py --sid 'sidA' --id $i --N $1 --f $2 --B $3 --S 100 --P "ng" --D True --O True --C $4 &
   ```
   for running Dumbo-NG with a batch size of 1000tx and a 20-epoch warm up can be:
   ```
   ./run_local_network_test.sh 4 1 1000 20
   ```
   
   To run Dumbo-DL, replace line 12 of run_local_network_test.sh with:
   ```
   python3 run_sockets_node.py --sid 'sidA' --id $i --N $1 --f $2 --B $3 --K $4 --S 100 --P "dl" --D True --O True &
   ```
   for 20 epochs with a batch size of 1000tx can be:
   ```
   ./run_local_network_test.sh 4 1 1000 20
   ```
   

3. If you would like to test the code among AWS cloud servers (with Ubuntu 18.84 LTS). You can follow the commands inside run_local_network_test.sh to remotely start the protocols at all servers. An example to conduct the WAN tests from your PC side terminal can be:
   ```
   # the number of remove AWS servers
   N = 4
   
   # public IPs --- This is the public IPs of AWS servers
    pubIPsVar=([0]='3.236.98.149'
    [1]='3.250.230.5'
    [2]='13.236.193.178'
    [3]='18.181.208.49')
    
   # private IPs --- This is the private IPs of AWS servers
    priIPsVar=([0]='172.31.71.134'
    [1]='172.31.7.198'
    [2]='172.31.6.250'
    [3]='172.31.2.176')
   
   # Clone code to all remote AWS servers from github
    i=0; while [ $i -le $(( N-1 )) ]; do
    ssh -i "/home/your-name/your-key-dir/your-sk.pem" -o StrictHostKeyChecking=no ubuntu@${pubIPsVar[i]} "git clone --branch release https://github.com/fascy/dumbo-ng.git" &
    i=$(( i+1 ))
    done
   
   # Update IP addresses to all remote AWS servers 
    rm tmp_hosts.config
    i=0; while [ $i -le $(( N-1 )) ]; do
      echo $i ${priIPsVar[$i]} ${pubIPsVar[$i]} $(( $((200 * $i)) + 10000 )) >> tmp_hosts.config
      i=$(( i+1 ))
    done
    i=0; while [ $i -le $(( N-1 )) ]; do
      ssh -o "StrictHostKeyChecking no" -i "/home/your-name/your-key-dir/your-sk.pem" ubuntu@${pubIPsVar[i]} "rm /home/ubuntu/dumbo-ng/hosts.config"
      scp -i "/home/your-name/your-key-dir/your-sk.pem" tmp_hosts.config ubuntu@${pubIPsVar[i]}:/home/ubuntu/dumbo-ng/hosts.config &
      i=$(( i+1 ))
    done
    
    # Start Protocols at all remote AWS servers
    i=0; while [ $i -le $(( N-1 )) ]; do   ssh -i "/home/your-name/your-key-dir/your-sk.pem" ubuntu@${pubIPsVar[i]} "export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib; export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib; cd dumbo-ng; nohup python3 run_socket_node.py --sid 'sidA' --id $i --N $N --f $(( (N-1)/3 )) --B 1000 --S 100 --P "ng" --C 20 > node-$i.out" &   i=$(( i+1 )); done
 
    # Download logs from all remote AWS servers to your local PC
    i=0
    while [ $i -le $(( N-1 )) ]
    do
      scp -i "/home/your-name/your-key-dir/your-sk.pem" ubuntu@${pubIPsVar[i]}:/home/ubuntu/dumbo-ng/log/node-$i.log node-$i.log &
      i=$(( i+1 ))
    done
 
   ```

Here down below is the original README.md of HoneyBadgerBFT


# HoneyBadgerBFT
The Honey Badger of BFT Protocols.

<img width=200 src="http://i.imgur.com/wqzdYl4.png"/>

[![Travis branch](https://img.shields.io/travis/initc3/HoneyBadgerBFT-Python/dev.svg)](https://travis-ci.org/initc3/HoneyBadgerBFT-Python)
[![Codecov branch](https://img.shields.io/codecov/c/github/initc3/honeybadgerbft-python/dev.svg)](https://codecov.io/github/initc3/honeybadgerbft-python?branch=dev)

HoneyBadgerBFT is a leaderless and completely asynchronous BFT consensus protocols.
This makes it a good fit for blockchains deployed over wide area networks
or when adversarial conditions are expected.
HoneyBadger nodes can even stay hidden behind anonymizing relays like Tor, and
the purely-asynchronous protocol will make progress at whatever rate the
network supports.

This repository contains a Python implementation of the HoneyBadgerBFT protocol.
It is still a prototype, and is not approved for production use. It is intended
to serve as a useful reference and alternative implementations for other projects.

## Development Activities

Since its initial implementation, the project has gone through a substantial
refactoring, and is currently under active development.

At the moment, the following three milestones are being focused on:

* [Bounded Badger](https://github.com/initc3/HoneyBadgerBFT-Python/milestone/3)
* [Test Network](https://github.com/initc3/HoneyBadgerBFT-Python/milestone/2<Paste>)
* [Release 1.0](https://github.com/initc3/HoneyBadgerBFT-Python/milestone/1)

A roadmap of the project can be found in [ROADMAP.rst](./ROADMAP.rst).


### Contributing
Contributions are welcomed! To quickly get setup for development:

1. Fork the repository and clone your fork. (See the Github Guide
   [Forking Projects](https://guides.github.com/activities/forking/) if
   needed.)

2. Install [`Docker`](https://docs.docker.com/install/). (For Linux, see
   [Manage Docker as a non-root user](https://docs.docker.com/install/linux/linux-postinstall/#manage-docker-as-a-non-root-user)
   to run `docker` without `sudo`.)

3. Install [`docker-compose`](https://docs.docker.com/compose/install/).

4. Run the tests (the first time will take longer as the image will be built):

   ```bash
   $ docker-compose run --rm honeybadger
   ```

   The tests should pass, and you should also see a small code coverage report
   output to the terminal.

If the above went all well, you should be setup for developing
**HoneyBadgerBFT-Python**!

## License
This is released under the CRAPL academic license. See ./CRAPL-LICENSE.txt
Other licenses may be issued at the authors' discretion.
