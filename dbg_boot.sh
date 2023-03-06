#!/bin/bash

export ORIG_PWD="$PWD"

cd ../linux-kernel-study
./dbg_boot.sh
cd $ORIG_PWD
