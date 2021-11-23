#!/bin/bash

source "bin/init/env.sh"
source "bin/plugin/pingtunnel/build.sh"

DIR="$ROOT/x86_64"
mkdir -p $DIR
env CC=$ANDROID_X86_64_CC GOARCH=amd64 go build -x -o $DIR/$LIB_OUTPUT -trimpath -ldflags="-s -w -buildid=" .

