#!/usr/bin/env bash

# NAME: raclient.sh
# DECRIPTION: Custom regsitration authority client used with ISC RAMI API
# AUTHOR: Tony Cavella (tony@cavella.com)
# SOURCE: https://github.com/acavella/trustedcore-ra

## CONFIGURE DEFAULT ENVIRONMENT
set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

## VARIABLES
__dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
__bin="${__dir}/bin"
__conf="${__dir}/conf"
dtgf=$(date '+%Y%m%d-%H%M%S')
ver=$(<VERSION)
config="${__conf}""/local.conf"
log="${__dir}""/log/raclient-""${dtgf}"".log"
start=$(date +%s)
reqs=("openssl" "curl" "sed")
arg1=${1}
arg2=${2}
arg3=${3:-}

make_temporary_log() {
    # Create a random temporary file for the log
    TEMPLOG=$(mktemp /tmp/raclient_temp.XXXXXX)
    # Open handle 3 for templog
    # https://stackoverflow.com/questions/18460186/writing-outputs-to-log-file-and-console
    exec 3>${TEMPLOG}
    # Delete templog, but allow for addressing via file handle
    # This lets us write to the log without having a temporary file on the drive, which
    # is meant to be a security measure so there is not a lingering file on the drive during the install process
    rm ${TEMPLOG}
}

copy_to_run_log() {
    # Copy the contents of file descriptor 3 into the log
    cat /proc/$$/fd/3 > "${log}"
    chmod 644 "${log}"
}

read_input() {
    local filesize=$(stat -c %s "${arg1}")
    subject=$(cat ${arg1})
    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Completed reading input file, ${filesize} bytes, ${arg1}"
}

generate_private_key() {
    if [[ ${arg2} == "rsa" ]]; then 
        openssl genrsa -out ${pkey} 4096
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Generated RSA private key, ${pkey} with a subject ${cn}"
    elif [[ ${arg2} == "ecdsa" ]]; then
        openssl ecparam -name secp384r1 -genkey -noout -out "${pkey}"
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Generated ECC private key, ${pkey} with a subject ${cn}"
    elif [[ ${arg2} == "ecdh" ]]; then
        openssl ecparam -name secp384r1 -genkey -noout -out "${pkey}"
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Generated ECC private key, ${pkey} with a subject ${cn}"
    else
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Unrecognized argument, ${arg2}, in second position"
        exit 1
    fi
}

generate_csr() { 
    local str="PKCS#10 CSR generated, ${csr}"
    if [[ ${arg2} == "rsa" ]]; then 
        sed -i -E "s/^(commonName[[:blank:]]*=[[:blank:]]*).*/\1${cn}/" ${__conf}/rsa.cnf
        openssl req -new -key "${pkey}" -nodes -out "${csr}" -sha384 -config "${__conf}/rsa.cnf"
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "${str}"
    elif [[ ${arg2} == "ecdsa" ]]; then
        sed -i -E "s/^(commonName[[:blank:]]*=[[:blank:]]*).*/\1${cn}/" ${__conf}/ecdsa.cnf
        openssl req -new -key "${pkey}" -nodes -out "${csr}" -sha384 -config "${__conf}/ecdsa.cnf"
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "${str}"
    elif [[ ${arg2} == "ecdh" ]]; then
        sed -i -E "s/^(commonName[[:blank:]]*=[[:blank:]]*).*/\1${cn}/" ${__conf}/ecdh.cnf
        openssl req -new -key "${pkey}" -nodes -out "${csr}" -sha384 -config "${__conf}/ecdh.cnf"
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "${str}"
    else
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Unrecognized argument, ${arg2}, exiting."
        exit 1
    fi
}

main() {

    read_input
    local counter=0
    local pid=$RANDOM
    local outputdir="${__dir}/output/${pid}"
    local csrdir="${outputdir}/csr"
    local pkeydir="${outputdir}/key"

    make_output_directory ${outputdir}
    make_output_directory ${csrdir}
    make_output_directory ${pkeydir}

    if [[ ${arg2} == "ecdsa" ]]; then
        caprofile=${ecdsaprofile}
    elif [[ ${arg2} == "ecdh" ]]; then
        caprofile=${ecdhprofile}
    elif [[ ${arg2} == "rsa" ]]; then
        caprofile=${rsaprofile}
    else
        exit 1
    fi

    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Generating private key and csr for each subject"
    for cn in $subject; do 

        local outputdir="${__dir}/output/${cn}"
        local csr="${outputdir}/${cn}.csr"
        local pkey="${outputdir}/${cn}.key"

        generate_private_key

        generate_csr

    done
}

make_temporary_log
main | tee -a /proc/$$/fd/3
copy_to_run_log