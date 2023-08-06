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

        local csr="${csrdir}/${cn}.csr"
        local pkey="${pkeydir}/${cn}.key"

        generate_private_key

        generate_csr

    done
}

make_temporary_log
main | tee -a /proc/$$/fd/3
copy_to_run_log