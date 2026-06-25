# build stage
# Base image digest-pinned for reproducible, supply-chain-verifiable builds.
# Bump the tag+digest together: docker inspect alpine:<tag> --format '{{index .RepoDigests 0}}'.
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d as build
RUN apk update &&\
    apk add --no-cache linux-headers alpine-sdk cmake tcl openssl-dev zlib-dev
WORKDIR /tmp
COPY . /tmp/srt-live-server/
# Pin SRT to a known-good commit on the belabox branch for reproducible builds.
# Bump source: https://github.com/irlserver/srt/tree/belabox
ARG SRT_COMMIT=f2297192ce9ab572464e84228efbc46f8c1eabf4
RUN git clone https://github.com/irlserver/srt.git
WORKDIR /tmp/srt
RUN git checkout ${SRT_COMMIT} && ./configure && make -j$(nproc) && make install
WORKDIR /tmp/srt-live-server
RUN git submodule update --init
RUN cmake . -DCMAKE_BUILD_TYPE=Release
RUN make -j$(nproc)

# final stage
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
ENV LD_LIBRARY_PATH /lib:/usr/lib:/usr/local/lib64
RUN apk update &&\
    apk add --no-cache openssl libstdc++ &&\
    adduser -D srt &&\
    mkdir /etc/sls /logs &&\
    chown srt /logs
COPY --from=build /usr/local/bin/srt-* /usr/local/bin/
COPY --from=build /usr/local/lib/libsrt* /usr/local/lib/
COPY --from=build /tmp/srt-live-server/bin/* /usr/local/bin/
COPY src/sls.conf /etc/sls/
VOLUME /logs
EXPOSE 8181 1936/udp
USER srt
WORKDIR /home/srt
ENTRYPOINT [ "srt_server", "-c", "/etc/sls/sls.conf"]
