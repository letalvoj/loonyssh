# Setup Rust development container for Codespaces

FROM mcr.microsoft.com/devcontainers/rust:0-1-bullseye

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
   && apt-get -y install clang lld pkg-config libfreetype6-dev libfontconfig1-dev\
   && apt-get autoremove -y && apt-get clean -y
