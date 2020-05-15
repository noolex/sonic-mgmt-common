#!/usr/bin/env bash

set -e

PATCH_DIR=$(dirname $(realpath ${BASH_SOURCE[0]}))

DEST_DIR=vendor
[ ! -z $1 ] && DEST_DIR=$1

if [ ! -d "${DEST_DIR}" ]; then
    echo "Unknown DEST_DIR \"${DEST_DIR}\""
    exit 1
fi

# Copy some of the packages from go mod download directory into vendor directory.
# It is a workaround for 'go mod vendor' not copying all files

[ -z ${GO} ] && GO=go
[ -z ${GOPATH} ] && GOPATH=$(${GO} env GOPATH)
PKGPATH=$(echo ${GOPATH} | sed 's/:.*$//g')/pkg/mod
COPY='rsync -r --chmod=u+w --exclude=testdata --exclude=*_test.go'

set -x

$COPY ${PKGPATH}/github.com/openconfig/ygot@v0.7.1/ygen \
    ${DEST_DIR}/github.com/openconfig/ygot/

$COPY ${PKGPATH}/github.com/openconfig/ygot@v0.7.1/genutil \
    ${DEST_DIR}/github.com/openconfig/ygot/

$COPY ${PKGPATH}/github.com/openconfig/ygot@v0.7.1/generator \
    ${DEST_DIR}/github.com/openconfig/ygot/

$COPY ${PKGPATH}/github.com/openconfig/goyang@v0.0.0-20200309174518-a00bece872fc/ \
    ${DEST_DIR}/github.com/openconfig/goyang/

$COPY ${PKGPATH}/github.com/openconfig/gnmi@v0.0.0-20200307010808-e7106f7f5493/ \
    ${DEST_DIR}/github.com/openconfig/gnmi/


# Apply patches

patch -d ${DEST_DIR}/github.com/openconfig -p1 < ${PATCH_DIR}/ygot/ygot.patch

patch -d ${DEST_DIR}/github.com/openconfig/goyang -p1 < ${PATCH_DIR}/goyang/goyang.patch

patch -d ${DEST_DIR}/github.com/antchfx/jsonquery -p1 < ${PATCH_DIR}/jsonquery.patch

patch -d ${DEST_DIR}/github.com/antchfx/xmlquery -p1 < ${PATCH_DIR}/xmlquery.patch

patch -d ${DEST_DIR}/github.com/antchfx/xpath  -p1 < ${PATCH_DIR}/xpath.patch

patch -d ${DEST_DIR}/github.com/golang/glog  -p1 < ${PATCH_DIR}/glog.patch

