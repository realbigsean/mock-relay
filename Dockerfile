FROM rustlang/rust:nightly-bullseye AS builder
RUN apt-get update && apt-get -y upgrade && apt-get install -y cmake libclang-dev
COPY . mock-relay
RUN cd mock-relay && make

FROM ubuntu:latest
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
  libssl-dev \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/mock-relay /usr/local/bin/mock-relay
