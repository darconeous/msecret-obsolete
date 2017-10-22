FROM ubuntu:yakkety

RUN apt-get -y update \
	&& DEBIAN_FRONTEND=noninteractive \
			apt-get install -y -q --no-install-recommends \
				libtool \
				autoconf-archive \
				vim \
				man \
				bsdtar \
				gcc g++ \
				pkg-config \
				autoconf \
				autoconf-archive \
				llvm \
				clang-3.8 clang++-3.8 \
				subversion \
				lcov \
				libfuzzer-3.8-dev \
				openssl \
				libssl-dev \
				automake

RUN ln -s /usr/bin/clang-3.8 /usr/bin/clang
RUN ln -s /usr/bin/clang++-3.8 /usr/bin/clang++
RUN ln -s /usr/bin/llvm-symbolizer-3.8 /usr/bin/llvm-symbolizer

