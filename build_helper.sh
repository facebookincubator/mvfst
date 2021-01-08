#!/bin/bash -eu

# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.


# This is a helpful script to build MVFST in the supplied dir
# It pulls in dependencies such as folly and fizz in the _build/deps dir.

# Obtain the mvfst repository root folder at the very start
MVFST_ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Useful constants
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_OFF="\033[0m"

usage() {
cat 1>&2 <<EOF

Usage ${0##*/} [-h|?] [-p PATH] [-i INSTALL_PREFIX]
  -p BUILD_DIR                           (optional): Path of the base dir for mvfst
  -i INSTALL_PREFIX                      (optional): install prefix path
  -m                                     (optional): Build folly without jemalloc
  -s                                     (optional): Skip installing system package dependencies
  -c                                     (optional): Use ccache
  -z                                     (optional): enable CCP support
  -f                                     (optional): Skip fetching dependencies (to test local changes)
  -h|?                                               Show this help message
EOF
}

FETCH_DEPENDENCIES=true
while getopts ":hp:i:msczf" arg; do
  case $arg in
    p)
      BUILD_DIR="${OPTARG}"
      ;;
    i)
      INSTALL_PREFIX="${OPTARG}"
      ;;
    m)
      MVFST_FOLLY_USE_JEMALLOC="n"
      ;;
    s)
      MVFST_SKIP_SYSTEM_DEPENDENCIES=true
      ;;
    c)
      MVFST_USE_CCACHE=true
      ;;
    z)
      MVFST_ENABLE_CCP=true
      ;;
    f)
      FETCH_DEPENDENCIES=false
      ;;
    h | *) # Display help.
      usage
      exit 0
      ;;
  esac
done

# Validate required parameters
if [ -z "${BUILD_DIR-}" ] ; then
  echo -e "${COLOR_RED}[ INFO ] Build dir is not set. So going to build into _build ${COLOR_OFF}"
  BUILD_DIR=_build
  mkdir -p $BUILD_DIR
fi

if [[ -n "${MVFST_FOLLY_USE_JEMALLOC-}" ]]; then
    if [[ "$MVFST_FOLLY_USE_JEMALLOC" != "n" ]]; then
        unset $MVFST_FOLLY_USE_JEMALLOC
    fi
fi

### Configure necessary build and install directories

cd $BUILD_DIR || exit
BWD=$(pwd)
DEPS_DIR=$BWD/deps
mkdir -p "$DEPS_DIR"

MVFST_BUILD_DIR=$BWD/build
mkdir -p "$MVFST_BUILD_DIR"

if [ -z "${INSTALL_PREFIX-}" ]; then
  FOLLY_INSTALL_DIR=$DEPS_DIR
  FIZZ_INSTALL_DIR=$DEPS_DIR
  LIBCCP_INSTALL_DIR=$DEPS_DIR
  MVFST_INSTALL_DIR=$BWD
else
  FOLLY_INSTALL_DIR=$INSTALL_PREFIX
  FIZZ_INSTALL_DIR=$INSTALL_PREFIX
  LIBCCP_INSTALL_DIR=$INSTALL_PREFIX
  MVFST_INSTALL_DIR=$INSTALL_PREFIX
fi

CMAKE_EXTRA_ARGS=(${CMAKE_EXTRA_ARGS-})
if [[ ! -z "${MVFST_USE_CCACHE-}" ]]; then
  CCACHE=$(which ccache)
  CMAKE_EXTRA_ARGS+=(-DCMAKE_C_COMPILER_LAUNCHER="${CCACHE}")
  CMAKE_EXTRA_ARGS+=(-DCMAKE_CXX_COMPILER_LAUNCHER="${CCACHE}")
fi

if [[ ! -z "${MVFST_FOLLY_USE_JEMALLOC-}" ]]; then
  CMAKE_EXTRA_ARGS+=(-DFOLLY_USE_JEMALLOC=0)
fi

# Default to parallel build width of 4.
# If we have "nproc", use that to get a better value.
# If not, then intentionally go a bit conservative and
# just use the default of 4 (e.g., some desktop/laptop OSs
# have a tendency to freeze if we actually use all cores).
set +x
nproc=4
if [ -z "$(hash nproc 2>&1)" ]; then
    nproc=$(nproc)
fi
set -x

function install_dependencies_linux() {
  sudo apt-get install        \
    g++                       \
    cmake                     \
    m4                        \
    libboost-all-dev          \
    libevent-dev              \
    libdouble-conversion-dev  \
    libgoogle-glog-dev        \
    libgflags-dev             \
    libiberty-dev             \
    liblz4-dev                \
    liblzma-dev               \
    libsnappy-dev             \
    make                      \
    zlib1g-dev                \
    binutils-dev              \
    libjemalloc-dev           \
    libssl-dev                \
    pkg-config                \
    libsodium-dev
}

function install_dependencies_mac() {
  # install the default dependencies from homebrew
  brew install               \
    cmake                    \
    m4                       \
    boost                    \
    double-conversion        \
    gflags                   \
    glog                     \
    libevent                 \
    lz4                      \
    snappy                   \
    xz                       \
    openssl                  \
    libsodium

  brew link                 \
    boost                   \
    double-conversion       \
    gflags                  \
    glog                    \
    libevent                \
    lz4                     \
    snappy                  \
    xz                      \
    libsodium
}

function setup_fmt() {
  FMT_DIR=$DEPS_DIR/fmt
  FMT_BUILD_DIR=$DEPS_DIR/fmt/build/

  if [ ! -d "$FMT_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fmt repo ${COLOR_OFF}"
    git clone https://github.com/fmtlib/fmt.git  "$FMT_DIR"
  fi
  cd "$FMT_DIR"
  git fetch --tags
  git checkout 6.2.1
  echo -e "${COLOR_GREEN}Building fmt ${COLOR_OFF}"
  mkdir -p "$FMT_BUILD_DIR"
  cd "$FMT_BUILD_DIR" || exit

  cmake                                             \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"                 \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"              \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo               \
    -DFMT_DOC=OFF                                   \
    -DFMT_TEST=OFF                                  \
    ${CMAKE_EXTRA_ARGS[@]+"${CMAKE_EXTRA_ARGS[@]}"} \
    ..
  make -j "$nproc"
  make install
  echo -e "${COLOR_GREEN}fmt is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

function setup_googletest() {
  GTEST_DIR=$DEPS_DIR/googletest
  GTEST_BUILD_DIR=$DEPS_DIR/googletest/build/

  if [ ! -d "$GTEST_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning googletest repo ${COLOR_OFF}"
    git clone https://github.com/google/googletest.git  "$GTEST_DIR"
  fi
  cd "$GTEST_DIR"
  git fetch --tags
  git checkout release-1.10.0
  echo -e "${COLOR_GREEN}Building googletest ${COLOR_OFF}"
  mkdir -p "$GTEST_BUILD_DIR"
  cd "$GTEST_BUILD_DIR" || exit

  cmake                                           \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"               \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"            \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo             \
    ..
  make -j "$nproc"
  make install
  echo -e "${COLOR_GREEN}googletest is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

function synch_dependency_to_commit() {
  # Utility function to synch a dependency to a specific commit. Takes two arguments:
  #   - $1: folder of the dependency's git repository
  #   - $2: path to the text file containing the desired commit hash
  if [ "$FETCH_DEPENDENCIES" = false ] ; then
    return
  fi
  DEP_REV=$(sed 's/Subproject commit //' "$2")
  pushd "$1"
  git fetch
  # Disable git warning about detached head when checking out a specific commit.
  git -c advice.detachedHead=false checkout "$DEP_REV"
  popd
}

function setup_folly() {
  FOLLY_DIR=$DEPS_DIR/folly
  FOLLY_BUILD_DIR=$DEPS_DIR/folly/build/

  if [ ! -d "$FOLLY_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning folly repo ${COLOR_OFF}"
    git clone https://github.com/facebook/folly.git "$FOLLY_DIR"
    if [[ -z "${MVFST_SKIP_SYSTEM_DEPENDENCIES-}" ]]; then
      echo -e "${COLOR_GREEN}[ INFO ] install dependencies ${COLOR_OFF}"
      if [ "$Platform" = "Linux" ]; then
        install_dependencies_linux
      elif [ "$Platform" = "Mac" ]; then
        install_dependencies_mac
      else
        echo -e "${COLOR_RED}[ ERROR ] Unknown platform: $Platform ${COLOR_OFF}"
        exit 1
      fi
    else
      echo -e "${COLOR_GREEN}[ INFO ] Skipping installing dependencies ${COLOR_OFF}"
    fi
  fi

  synch_dependency_to_commit "$FOLLY_DIR" "$MVFST_ROOT_DIR/build/deps/github_hashes/facebook/folly-rev.txt"

  if [ "$Platform" = "Mac" ]; then
    # Homebrew installs OpenSSL in a non-default location on MacOS >= Mojave
    # 10.14 because MacOS has its own SSL implementation.  If we find the
    # typical Homebrew OpenSSL dir, load OPENSSL_ROOT_DIR so that cmake
    # will find the Homebrew version.
    dir=/usr/local/opt/openssl
    if [ -d $dir ]; then
        export OPENSSL_ROOT_DIR=$dir
    fi
  fi

  echo -e "${COLOR_GREEN}Building Folly ${COLOR_OFF}"
  mkdir -p "$FOLLY_BUILD_DIR"
  cd "$FOLLY_BUILD_DIR" || exit

  # check for environment variable. If
  cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo           \
    -DCMAKE_PREFIX_PATH="$FOLLY_INSTALL_DIR"        \
    -DCMAKE_INSTALL_PREFIX="$FOLLY_INSTALL_DIR"     \
    ${CMAKE_EXTRA_ARGS[@]+"${CMAKE_EXTRA_ARGS[@]}"} \
    ..
  make -j "$nproc"
  make install
  echo -e "${COLOR_GREEN}Folly is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

function setup_fizz() {
  FIZZ_DIR=$DEPS_DIR/fizz
  FIZZ_BUILD_DIR=$DEPS_DIR/fizz/build/
  if [ ! -d "$FIZZ_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fizz repo ${COLOR_OFF}"
    git clone https://github.com/facebookincubator/fizz "$FIZZ_DIR"
  fi

  synch_dependency_to_commit "$FIZZ_DIR" "$MVFST_ROOT_DIR/build/deps/github_hashes/facebookincubator/fizz-rev.txt"

  echo -e "${COLOR_GREEN}Building Fizz ${COLOR_OFF}"
  mkdir -p "$FIZZ_BUILD_DIR"
  cd "$FIZZ_BUILD_DIR" || exit
  cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo           \
    -DBUILD_TESTS=OFF                               \
    -DCMAKE_PREFIX_PATH="$FIZZ_INSTALL_DIR"         \
    -DCMAKE_INSTALL_PREFIX="$FIZZ_INSTALL_DIR"      \
    ${CMAKE_EXTRA_ARGS[@]+"${CMAKE_EXTRA_ARGS[@]}"} \
    "$FIZZ_DIR/fizz"
  make -j "$nproc"
  make install
  echo -e "${COLOR_GREEN}Fizz is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

function detect_platform() {
  unameOut="$(uname -s)"
  case "${unameOut}" in
      Linux*)     Platform=Linux;;
      Darwin*)    Platform=Mac;;
      *)          Platform="UNKNOWN:${unameOut}"
  esac
  echo -e "${COLOR_GREEN}Detected platform: $Platform ${COLOR_OFF}"
}

function setup_libccp() {
  LIBCCP_DIR=$DEPS_DIR/libccp
  LIBCCP_BUILD_DIR=$LIBCCP_DIR/build/
  if [ ! -d "$LIBCCP_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning libccp repo ${COLOR_OFF}"
    git clone https://github.com/ccp-project/libccp "$LIBCCP_DIR"
  fi

  #synch_dependency_to_commit "$LIBCCP_DIR" "$MVFST_ROOT_DIR/build/deps/github_hashes/libccp-rev.txt"

  echo -e "${COLOR_GREEN}Building libccp ${COLOR_OFF}"
  mkdir -p "$LIBCCP_BUILD_DIR"
  cd "$LIBCCP_BUILD_DIR" || exit
  cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo           \
    -DBUILD_TESTS=OFF                               \
    -DCMAKE_PREFIX_PATH="$LIBCCP_INSTALL_DIR"       \
    -DCMAKE_INSTALL_PREFIX="$LIBCCP_INSTALL_DIR"    \
    -DCMAKE_CXX_FLAGS=\D__CPLUSPLUS__=1             \
    ${CMAKE_EXTRA_ARGS[@]+"${CMAKE_EXTRA_ARGS[@]}"} \
    "$LIBCCP_DIR"
  make -j "$nproc"
  make install
  echo -e "${COLOR_GREEN}libccp is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

function setup_rust() {
  if ! [ -x "$(command -v rustc)" ] || ! [ -x "$(command -v cargo)" ]; then
    echo -e "${COLOR_RED}[ ERROR ] Rust not found (required for CCP support).${COLOR_OFF}\n"
    echo -e "    To install rust, run the following command, then rerun build_helper.sh:\n"
    echo -e "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y\n"
    echo -e "    You may also need to run \`source $HOME/.cargo/env\` after installing to add rust to your PATH.\n\n"
    exit
  else
    echo -e "${COLOR_GREEN}[ INFO ] Found rust (required for CCP support).${COLOR_OFF}"
  fi
}

detect_platform
setup_fmt
setup_googletest
setup_folly
setup_fizz
if [[ -n "${MVFST_ENABLE_CCP-}" ]]; then
  setup_libccp
  setup_rust
fi


# build mvfst:
cd "$MVFST_BUILD_DIR" || exit
mvfst_cmake_build_args=(
  -DCMAKE_PREFIX_PATH="$FOLLY_INSTALL_DIR"        \
  -DCMAKE_INSTALL_PREFIX="$MVFST_INSTALL_DIR"     \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo               \
  -DBUILD_TESTS=On                                \
  ${CMAKE_EXTRA_ARGS[@]+"${CMAKE_EXTRA_ARGS[@]}"} \
)
if [[ -n "${MVFST_ENABLE_CCP-}" ]]; then
    mvfst_cmake_build_args+=(-DCCP_ENABLED=TRUE)
fi
cmake "${mvfst_cmake_build_args[@]}" ../..
make -j "$nproc"

echo -e "${COLOR_GREEN}MVFST build is complete. To run unit test: \
  cd _build/build && make test ${COLOR_OFF}"
