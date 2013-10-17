#!/bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Usage: ./generate_certs.sh <path to objdir> <output directory>
# e.g. (from the root of mozilla-central)
# `./generate_certs.sh obj-x86_64-unknown-linux-gnu/ .'
#
# NB: This will cause the following files to be overwritten if they are in
# the output directory:
#  cert8.db, key3.db, secmod.db, {many}.pem
set -x
set -e

if [ $# -ne 2 ]; then
  echo "Usage: `basename ${0}` <path to objdir> <output directory>"
  exit $E_BADARGS
fi

OBJDIR=${1}
OUTPUT_DIR=${2}
RUN_MOZILLA="$OBJDIR/dist/bin/run-mozilla.sh"
CERTUTIL="$OBJDIR/dist/bin/certutil"

NOISE_FILE=`mktemp`
dd if=/dev/urandom of="$NOISE_FILE" bs=1024 count=1
PASSWORD_FILE=`mktemp`

function cleanup {
  rm -f "$NOISE_FILE" "$PASSWORD_FILE"
}

if [ ! -f "$RUN_MOZILLA" ]; then
  echo "Could not find run-mozilla.sh at \'$RUN_MOZILLA\'"
  exit $E_BADARGS
fi

if [ ! -f "$CERTUTIL" ]; then
  echo "Could not find certutil at \'$CERTUTIL\'"
  exit $E_BADARGS
fi

if [ ! -d "$OUTPUT_DIR" ]; then
  echo "Could not find output directory at \'$OUTPUT_DIR\'"
  exit $E_BADARGS
fi

if [ -f "$OUTPUT_DIR/cert8.db" -o -f "$OUTPUT_DIR/key3.db" -o -f "$OUTPUT_DIR/secmod.db" ]; then
  echo "Found pre-existing NSS DBs. Clobbering old OCSP certs."
  rm -f "$OUTPUT_DIR/cert8.db" "$OUTPUT_DIR/key3.db" "$OUTPUT_DIR/secmod.db"
fi
$RUN_MOZILLA $CERTUTIL -d $OUTPUT_DIR -N -f $PASSWORD_FILE

COMMON_ARGS="-v 360 -w -1 -2 -z $NOISE_FILE"
DEFAULT_KEY_SIZE=2048

function make_CA {
  CA_RESPONSES="y\n0\ny"
  NICKNAME="${1}"
  SUBJECT="${2}"
  PEMFILE="${3}"
  if [ -z "$KEY_SIZE" ]; then
    KEY_SIZE="$DEFAULT_KEY_SIZE"
  fi

  echo -e "$CA_RESPONSES" | $RUN_MOZILLA $CERTUTIL -d $OUTPUT_DIR -S \
                                                   -n $NICKNAME \
                                                   -s "$SUBJECT" \
                                                   -t "CT,," \
                                                   -g "$KEY_SIZE" \
                                                   -x $COMMON_ARGS
  $RUN_MOZILLA $CERTUTIL -d $OUTPUT_DIR -L -n $NICKNAME -a > $OUTPUT_DIR/$PEMFILE
  unset KEY_SIZE
}

function make_INT {
  INT_RESPONSES="y\n0\ny"
  NICKNAME="${1}"
  SUBJECT="${2}"
  CA="${3}"
  PEMFILE="${4}"
  if [ -z "$KEY_SIZE" ]; then
    KEY_SIZE="$DEFAULT_KEY_SIZE"
  fi

  echo -e "$INT_RESPONSES" | $RUN_MOZILLA $CERTUTIL -d $OUTPUT_DIR -S \
                                                    -n $NICKNAME \
                                                    -s "$SUBJECT" \
                                                    -c "$CA" \
                                                    -t ",," \
                                                    -g "$KEY_SIZE" \
                                                    -x $COMMON_ARGS
  $RUN_MOZILLA $CERTUTIL -d $OUTPUT_DIR -L -n $NICKNAME -a > $OUTPUT_DIR/$PEMFILE
  unset KEY_SIZE
}

SERIALNO=1

function make_EE {
  EE_RESPONSES="n\n\ny"
  NICKNAME="${1}"
  SUBJECT="${2}"
  CA="${3}"
  PEMFILE="${4}"
  SUBJECT_ALT_NAME="${5}"
  if [ -n "$SUBJECT_ALT_NAME" ]; then
    SUBJECT_ALT_NAME="-8 $SUBJECT_ALT_NAME"
  fi
  if [ -z "$KEY_SIZE" ]; then
    KEY_SIZE="$DEFAULT_KEY_SIZE"
  fi

  echo -e "$EE_RESPONSES" | $RUN_MOZILLA $CERTUTIL -d $OUTPUT_DIR -S \
                                                     -n $NICKNAME \
                                                     -s "$SUBJECT" \
                                                     $SUBJECT_ALT_NAME \
                                                     -c $CA \
                                                     -t ",," \
                                                     -m $SERIALNO \
                                                     -g "$KEY_SIZE" \
                                                     $COMMON_ARGS
  $RUN_MOZILLA $CERTUTIL -d $OUTPUT_DIR -L -n $NICKNAME -a > $OUTPUT_DIR/$PEMFILE
  SERIALNO=$(($SERIALNO + 1))
  unset KEY_SIZE
}

make_CA goodCA 'CN=Good CA,O=Good Organization,C=US' goodCA.pem
make_INT goodINT 'CN=Good Intermediate CA,O=Good Organization,C=US' goodCA goodINT.pem 
make_INT badINT 'CN=Bad Intermediate CA' goodCA badINT.pem 
make_EE goodEE 'CN=good.example.com' goodINT goodEE.pem "good.example.com"
make_EE altnamesEE 'CN=good2.example.com' goodINT altnamesEE.pem "good2.example.com,good2.example.org,127.0.0.1"
make_EE altnameMismatchEE 'CN=mismatch.example.com' goodINT altnameMismatchEE.pem "mismatch.example.org"
KEY_SIZE=1024
make_EE everythingWrongEE 'CN=everythingWrong.example.com' badINT everythingWrongEE.pem

cleanup
