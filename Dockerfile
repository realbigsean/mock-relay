FROM rust:1.67.1-bullseye AS builder
RUN apt-get update && apt-get -y upgrade && apt-get install -y cmake libclang-dev protobuf-compiler
COPY . mock-relay
RUN cd mock-relay && make 

FROM ubuntu:22.04
RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/mock-relay /usr/local/bin/mock-relay
