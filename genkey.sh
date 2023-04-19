#!/bin/bash

ROOTPATH="${PWD}"

# make directories to work from
mkdir -p $ROOTPATH/certs/{server,client,ca,tmp}

PATH_CA=$ROOTPATH/certs/ca
PATH_SERVER=$ROOTPATH/certs/server
PATH_CLIENT=$ROOTPATH/certs/client

RSABITS=4096
EXPIREDAYS=365

GK_C=""
GK_ST=""
GK_L=""
GK_O="Example Inc"
GK_OU=""
GK_CN="local.example"
GK_emailAddress=""
GK_unstructuredName=""

if [ ! -z "$GK_C" ]; then
    GK_C="/C=$GK_C"
fi

if [ ! -z "$GK_ST" ]; then
    GK_ST="/ST=$GK_ST"
fi

if [ ! -z "$GK_L" ]; then
    GK_L="/L=$GK_L"
fi

if [ ! -z "$GK_O" ]; then
    GK_O="/O=$GK_O"
fi

if [ ! -z "$GK_OU" ]; then
    GK_OU="/OU=$GK_OU"
fi

if [ ! -z "$GK_CN" ]; then
    GK_CN="/CN=$GK_CN"
else
    echo "Missing common name!"
    exit 1
fi

if [ ! -z "$GK_emailAddress" ]; then
    GK_emailAddress="/emailAddress=$GK_emailAddress"
fi

if [ ! -z "$GK_unstructuredName" ]; then
    GK_unstructuredName="/unstructuredName=$GK_unstructuredName"
fi

EXTRA_FIELDS=""

echo -e "\n##################"
echo -e "# Generate certs #"
echo -e "##################\n"

######
# CA #
######

echo -e "# CA\n"

openssl genrsa -out $PATH_CA/ca.key $RSABITS

# Create Authority Certificate
openssl req -new -x509 -days $EXPIREDAYS -key $PATH_CA/ca.key -out $PATH_CA/ca.crt -subj "/C=$GK_C/ST=$GK_ST/L=$GK_L/O=$GK_O/OU=$GK_OU/CN=.$GK_unstructuredName$GK_emailAddress$EXTRA_FIELDS"

##########
# SERVER #
##########

echo -e "\n# Server\n"

# Generate server key
openssl genrsa -out $PATH_SERVER/server.key $RSABITS

# Generate server cert
openssl req -new -key $PATH_SERVER/server.key -out $PATH_SERVER/server.csr -subj "/C=$GK_C/ST=$GK_ST/L=$GK_L/O=$GK_O/OU=$GK_OU/CN=$GK_CN$GK_unstructuredName$GK_emailAddress$EXTRA_FIELDS"

# Sign server cert with self-signed cert
openssl x509 -req -days $EXPIREDAYS -passin pass:$PASSWORD -in $PATH_SERVER/server.csr -CA $PATH_CA/ca.crt -CAkey $PATH_CA/ca.key -set_serial 01 -out $PATH_SERVER/server.crt

##########
# CLIENT #
##########

echo -e "\n# Client\n"

openssl genrsa -out $PATH_CLIENT/client.key $RSABITS

openssl req -new -key $PATH_CLIENT/client.key -out $PATH_CLIENT/client.csr -subj "/C=$GK_C/ST=$GK_ST/L=$GK_L/O=$GK_O/OU=$GK_OU/CN=CLIENT$GK_unstructuredName$GK_emailAddress$EXTRA_FIELDS"

openssl x509 -req -days 365 -in $PATH_CLIENT/client.csr -CA $PATH_CA/ca.crt -CAkey $PATH_CA/ca.key -set_serial 01 -out $PATH_CLIENT/client.crt

echo -e "\nDone !"

exit 0
