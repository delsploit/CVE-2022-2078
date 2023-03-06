#!/bin/bash

export ORIG_PWD="$PWD"

cd ../linux-kernel-study
./boot.sh
cd $ORIG_PWD
