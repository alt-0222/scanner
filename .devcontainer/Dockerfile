# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.245.2/containers/rust/.devcontainer/base.Dockerfile

# [Choice] Debian OS version (use bullseye on local arm64/Apple Silicon): buster, bullseye
ARG VARIANT="bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/rust:0-${VARIANT}

# [Optional] Uncomment this section to install additional packages.
# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
#     && apt-get -y install --no-install-recommends <your-package-list-here>
FROM golang:1.18 AS go

FROM ubuntu:latest

RUN apt update && apt upgrade -y

RUN apt install -y gcc curl wget git vim zip sqlite3 libdigest-sha-perl zsh build-essential make libzstd-dev pkg-config htop

ARG USER=alt-0222

RUN adduser \
   --system \
   --shell /bin/bash \
   --gecos $USER \
   --group \
   --disabled-password \
   --home /home/$USER \
   $USER

USER $USER
COPY bashrc /home/$USER/.bashrc

# Setup go
RUN mkdir -p /home/$USER/.local/gopath

COPY --from=go /usr/local/go /home/$USER/.local/go

ENV GOROOT /home/$USER/.local/go
ENV GOPATH /home/$USER/.local/gopath
ENV PATH $PATH:$GOPATH/bin:$GOROOT/bin


# Set up Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y

USER root

EXPOSE 8000 8080