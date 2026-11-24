# Botnet Analysis Automation

Project for automating threat intel for automated Botnet attacks. 

## Project background

Marek Contofalsky developed the original system in 2024 and 2025 as part of his
bachelor's thesis. For details on the project's origins, design, and evaluation,
see [*Analýza kybernetických útokov v honeypot prostrediach*](https://opac.crzp.sk/?fn=detailBiblioForm&sid=F3AF90715DF24108A63E13E80399)
in the Slovak Central Register of Theses (CRZP).


## Prerequisites

Python 3.10+

## Installation

```bash
sudo apt update && sudo apt upgrade

sudo apt install python3-pip podman git sshpass redis-server

git clone git@github.com:MarekConto/botnet_analysis_automation.git && cd botnet_analysis_automation/

pip3 install -r requirements.txt

bash setup.sh
```

## Starting the system

```bash
bash start.sh
```

## Stopping the system

```bash
bash stop.sh
```

> **Note**: The system expects Suricata logs in `botnet_analysis_automation/log.json`

> **Redis**: Internal communication between Python modules uses Redis Streams. `start.sh` starts a local `redis-server` when it is installed and not already running.

> **Log files**: Output logs of background modules (`*.py`) are stored in the `script_logs/` directory. 

## Optional

### Building Podman images manually

If you prefer to build the Docker/Podman images yourself instead of pulling them from Docker Hub, the corresponding `Dockerfile`s are provided in the `extractors/` directory.

You can build them using:

```bash
# Example build command
podman build -t <tool> . 
```

Make sure to clone or download the source code of each extractor before building.

The extractors used in this project are open source and available here:

- **miraicfg** – [https://github.com/FernandoDoming/miraicfg](https://github.com/FernandoDoming/miraicfg)
- **mozibgone** – [https://github.com/cartoon-raccoon/mozibgone](https://github.com/cartoon-raccoon/mozibgone)
- **mozitools** – [https://github.com/kn0wl3dge/mozitools](https://github.com/kn0wl3dge/mozitools)

In the case of building your own images, make sure the names and commands in the `EXTRACTORS` variable of the `extract_configuration.py` matches your image configuration.


## License

The project code is available under the [MIT License](LICENSE). The included
[Cowrie](https://github.com/cowrie/cowrie) configuration is subject to
Cowrie's BSD license. The offline image includes
[`mozibgone`](https://github.com/cartoon-raccoon/mozibgone) under its
MIT license.
   