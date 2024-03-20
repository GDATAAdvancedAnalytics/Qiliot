# Qiliot

An environment developed for the emulation of destructive IoT malware based on Qiling.
[Qiling](https://docs.qiling.io/en/latest/) is an isolated emulation tool that can emulate any sample (architecture-independent) on any operating system (also architecture-independent). Additionally, Docker's filesystem isolation is utilized.
(Note: Docker does not offer complete isolation, hence malware analysis should never be performed in a Docker container but always in a VM).
The benefit in this case is to prevent the accidental dynamic mounting of storage devices in Qiling. The malware is only emulated and runs solely on the MIPS architecture.

Implemented hooks for:
    - AcidRain [coming soon]

## Description

Docker constructs the environment for Qiling. Within docker compose, volumes are set to store the extracted files from emulation environment.
The Qiliot script is started via the script in the project folder "qiling/run_qiliot.sh".
This script is called and executed through docker compose.


## Patches
Qiling has a bug in the `getdents64` syscall for the MIPS architecture. We have fixed it and created a pull request: https://github.com/qilingframework/qiling/pull/1425, which has not been merged yet.
Once this PR is merged, the alignment patch in `patches/unistd.patch` will become obsolete.

The `lseek` patch in patches/unistd.patch addresses specific issues with file seeking operations.

All other patches are not required; they just assist in enhancing functionality, such as making directory names readable in logs.

### Logs

In a log file per emulation, all data captured by `ql.log` is collected. This also includes data from each process.
Logs are stored in the project folder under "logs/".

## Run Qiliot locally in Docker

### Setting Up the Environment

Only Docker and docker compose are required.
For the initial call or changes, the command `docker compose up --build` must be executed.
Afterwards, nothing further needs to be done except to start everything with `docker compose up` (or `docker compose up`).


### Rebuilding the Environment

For changes, the container and the image must be deleted and then rebuilt with the command `docker compose up --build`.
The `refresh_container.sh` script can be used for this purpose.

## Run Qiliot locally (not recommended)

For local execution of Qiliot, preferably a virtualenv is required.
There, `pip install qiling==1.4.6 pefile==2023.2.7 patch` must be used to install the required packages.
Subsequently, Qiliot can be executed, e.g., with `qiliot.py -b PATH_TO_SAMPLE -r ../rootfs -l DEFAULT`.
Currently, this only works under Linux x86_64.