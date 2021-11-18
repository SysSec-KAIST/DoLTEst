FROM ubuntu:18.04
LABEL "about"="DoLTEst base img"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y && \
    apt install -y git cmake libfftw3-dev libmbedtls-dev\
          libboost-program-options-dev libconfig++-dev\
          libsctp-dev\
          libuhd-dev         
#libpcsclite-dev pcsc-tools pcscd\

RUN mkdir DoLTEst

COPY ./ DoLTEst/

RUN rm -rf DoLTEst/build
RUN mkdir DoLTEst/build
WORKDIR /DoLTEst/build

RUN cmake ..
RUN make -j4 

RUN /usr/lib/uhd/utils/uhd_images_downloader.py


