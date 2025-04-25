> *Faster Hash-based Multi-valued Validated Asynchronous Byzantine Agreement* Accepted by [DSN 2025](https://dsn2025.github.io/cpaccepted.html).

# Implementation of "Faster Hash-based Multi-valued Validated Asynchronous Byzantine Agreement"

This codebase contains a proof-of-concept implementation of the hash-based MVBA in the paper [*Faster Hash-based Multi-valued Validated Asynchronous Byzantine Agreement*](dsn25-paper239.accepted-version.pdf), based on [Dumbo-NG](https://github.com/yylluu/Dumbo_NG).

This codebase also includes PoC implementation of FIN-MVBA in [FIN: Practical Signature-Free Asynchronous Common Subset in Constant Time](https://dl.acm.org/doi/10.1145/3576915.3616633), sMVBA★-BLS and sMVBA★-ECDSA, whose full descriptions can be found in the accepted paper.

## Code structure

The following is a brief introduction to the directory structure of this artifact:
```{text}
├── crypto                  # Implementation of cryptographic primitives.
├── docker                  # Docker supports
├── dsn25-paper239.accepted-version.pdf     # Paper (accepted version)
├── dumbomvba               # Legacy code in Dumbo_NG
├── dumbomvbastar           # Implementation of sMVBA★-ECDSA
├── dumbomvbastar_bls       # Implementation of sMVBA★-BLS
├── fin_mvba                # Implementation of FIN-MVBA, including its RABA subprotocols pillar and pisa
├── hash_mvba               # Implementation of our hash-based MVBA, including the MBA subprotocol
├── honeybadgerbft          # Legacy code in Honeybadger BFT
├── hosts.config            # See below "Communication model"
├── mvba_node               # Contain testing classes and helper functions
│   ├── dumbo_node.py       # Contain runner class for testing Dumbo MVBAs
│   ├── make_random_tx.py   # Produce random transactions
│   └── node.py             # Contain runner class for testing hash-based MVBAs
├── network                 # Server and client classes that handle socket communications
├── non_docker              # Shell scripts to set up running environment on bluk non-Docker OSs
├── README.md
├── run_local_network_mvba_test.sh      # Helper shell script for running local tests
├── run_socket_mvba_node.py # Python test framework
├── run_trusted_key_gen.py  # Helper script to generate keys for non-hash-based MVBAs
├── speedmvba               # Legacy code in Dumbo_NG
├── speedmvba_bls           # Modified based on speedmvba
├── test_dumbomvbastar_bls.sh       # Local test script for sMVBA★-BLS
├── test_dumbomvbastar.sh   # Local test script for sMVBA★-ECDSA
├── test_finmvba.sh         # Local test script for FIN MVBA
└── test_hmvba.sh           # Local test script for our hash-based MVBA
```

Specifically, MVBA implementations are at the following locations:
- Our hash-based MVBA: `hash_mvba.core.hmvba_protocol.run_hmvba`
- FIN-MVBA: `fin_mvba.core.fin_mvba_protocol.run_fin_mvba`
- sMVBA★-BLS: `dumbomvbastar_bls.core.dumbomvba_star.smvbastar`
- sMVBA★-ECDSA: `dumbomvbastar.core.dumbomvba_star.smvbastar`

## Communication model and configurations

We establish point-to-point communication channels between every two nodes via unauthenticated TCP sockets. 
To make this possible, one must prepare a valid and static `hosts.config` beforehand. `hosts.config` is a global address book shared by all nodes. The `i`-th line specifies the IP address and the receiving port of the `i`-th instance whose `pid` is `i` (assume `0`-indexing). 
Suppose the `i`-th line of `hosts.config` is `a.b.c.d X`, then the `i`-th instance should bind to IP address `a.b.c.d` and the receiving port `X`. It reserves the next `N` consecutive ports `[X+1, X+N]` as sending ports where port `X+j` of the `i`-th instance only handles outgoing data to the `j`-th instance with `pid=j`. This port binding convention is helpful to keep track of all communication pairs.

### Address book format

Each line of the `hosts.config` should contain an IP address and a port number. When the port number is omitted, a default receiving port `10000` is used. 
When `localhost` or `127.0.0.1` is specified as the IP address of a node, the receiving port is hard-coded as `pid * 200`. The processing of address book is in `run_socket_mvba_node.py`.

For example, with the following address book, a test can be run among five nodes.
- The `0`-th node binds to `200.0.0.1` and listens to port `10000`. It will attempt to establish TCP connection to `200.0.0.1:10000`, `200.0.0.2:1234`, `200.0.0.3:1111`, `200.0.0.4:2222`, `180.0.0.4:9889` from port `10001` to `10005`.
- The `4`-th node binds to `180.0.0.4` and listens to port `9889`. It will attempt to establish TCP connection to `200.0.0.1:10000`, `200.0.0.2:1234`, `200.0.0.3:1111`, `200.0.0.4:2222`, `180.0.0.4:9889` from port `9890` to `9894`.

```{text}
200.0.0.1
200.0.0.2 1234
200.0.0.3 1111
200.0.0.4 2222
180.0.0.4 9889
```

## Supported environment and required specification

Our implementation has been tested on (1) AWS `t2.medium` EC2 instances with Amazon Linux 2023 as the operating system, and (2) Debian-based Docker images. 
`t2.medium` instances have 2 Intel Xeon processors of speed up to 3.4 GHz Turbo CPU clock and 4 GB memory, whereas the host machine of the Docker has a 13th Gen Intel i9-13900 CPU processor with 32 cores and of up to 5.6 GHz CPU clock, and 32 GB memory.

For local testing or cluster testing, we highly recommend 1GB RAM per running node. Note that memory usage will increase when the testing batch size increases.

## Setup running environments

### Docker setup

We utilize `docker` to prepare an isolated and reusable environment for this codebase.

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

### Non-docker setup

We provide two setup shell scripts in [./non_docker](non_docker) folder to support manual setup. Note that this may pollute your OS or break existing dependencies in your OS. 

- [/non_docker/amazonlinux_setup.sh](/non_docker/amazonlinux_setup.sh) will set up the environment on the AWS EC2 default OS, `amazonlinux 2023`. 
- [/non_docker/debian_setup.sh](/non_docker/debian_setup.sh) will set up the environment on Debian-based OS. It will overwrite default Python to Python 3.8.

If you do wish to manually set up a non-isolated environment on a different OS, please consult the above shell scripts thus the [docker/env.Dockerfile](docker/env.Dockerfile) to understand how dependencies should be installed.

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

## Reproducibility support

Our test runner `run_socket_mvba_node.py` requires a global address book `hosts.config` (explained in Section [Communication model and configurations](#communication-model-and-configurations)) and a collection of parameters. 
We demonstrate the parameters in an exemplar shell script `run_local_network_mvba_test.sh` and provide a more detailed explanation below. 

To run `run_socket_mvba_node.py`, we need six parameters along with the address book and a working environment. The parameters are: 
- `$1`: the number of nodes in the whole testing network.
- `$2`: the number of Byzantine nodes that the protocol expects to tolerate.
- `$3`: the batch size. Each batch is a random string of 250 bytes.
- `$4`: the number of time to repeat testing.
- `$5`: the "warm up" counter, the number of repeats needed to warm up the system before the actual measurement of the performance of the protocol.
- `$6`: the protocol to be tested. Valid protocols are:
    - `hmvba`: our hash-based MVBA
    - `dumbomvbastar`: sMVBA★-ECDSA
    - `dumbomvbastarbls`: sMVBA★-BLS
    - `finmvba`: FIN-MVBA

When `N` instances completes running the experiment, one needs to collect the `*.stdout.log` logs of all nodes, and extract the latency data from these logs. The throughput measurement can be derived from dividing the batch size by the latency.

## Limitations

- Scripts that automate cloud-based experiments on AWS are not provided. We adapted and customized the cloud testing framework in https://zenodo.org/doi/10.5281/zenodo.12736462.
- Due to limitation of computation resources, the results in the original paper cannot be reproduced locally.

---

This codebase is developed based on [Dumbo-NG](https://github.com/yylluu/Dumbo_NG), and we provided the original README at [./legacy_README.md](./legacy_README.md).