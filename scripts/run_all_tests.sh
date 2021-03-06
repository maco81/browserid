#!/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"
BASEDIR=$(dirname $SCRIPT_DIR)
export PATH=$PATH:$SCRIPT_DIR/../node_modules/.bin

VOWS=`which vows 2> /dev/null`
if [ ! -x "$VOWS" ]; then
    echo "vows not found in your path.  try:  npm install"
    exit 1
fi

# vows hates absolute paths.  sheesh.
cd $BASEDIR

for env in test_mysql test_json ; do
  export NODE_ENV=$env
  $SCRIPT_DIR/test_db_connectivity.js
  if [ $? = 0 ] ; then
      echo "Testing with NODE_ENV=$env"
      for file in tests/*.js ; do
          echo $file
          vows $file
          if [[ $? != 0 ]] ; then
              exit 1
          fi
      done
  else
      echo "CANNOT TEST '$env' ENVIRONMENT: can't connect to the database"
  fi
done
