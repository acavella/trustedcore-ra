#!/usr/bin/env bash

# NAME: signcert.sh
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
ver=$(<VERSION)
config="${__conf}""/local.conf"
log="${__dir}""/log/tcra-""${dtgf}"".log"
reqs=("openssl" "curl" "sed")
arg1=${1}
arg2=${2:-default}
arg3=${3:-default}

# Log start time
start=$(date +%s)

make_temporary_log() {
    # Create a random temporary file for the log
    TEMPLOG=$(mktemp /tmp/tcra_temp.XXXXXX)
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

set_profile() {
    if [[ ${arg2} == "ecdsa" ]]; then
        caprofile=${ecdsaprofile}
        caurl=${caecc}
    elif [[ ${arg2} == "ecdh" ]]; then
        caprofile=${ecdhprofile}
        caurl=${caecc}
    elif [[ ${arg2} == "rsa" ]]; then
        caprofile=${rsaprofile}
        caurl=${carsa}
    else
        exit 1
    fi
}

start() {
    # Print startup and debug information
    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Trusted Core: RA v${ver} - Sign Certificate"
    
    # Load local configuration 
    if [ ! -e $config ]
    then
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Configuration file missing"
        exit 1
    else
        source $config
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Configuration file loaded sucessfully, ${config}"
    fi

    # Check for requirements, exit if not found
    for req in ${reqs[@]}; do
        if is_command ${req} ; then
            printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Command ${req} was found"
        else
            printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Command ${req} was not found, exiting"
            exit 1
        fi
    done
}

main() {

    local targetdir="${__dir}/output/${dtgf}"
    local p7header="-----BEGIN PKCS7-----"
    local p7footer="-----END PKCS7-----"
    local tempout=$(mktemp /tmp/temp.XXXXXXXXX)

    
    start 
    set_profile

    for file in ${arg1}*
    do
        local request=$(sed -e '2,$!d' -e '$d' ${file} | tr --delete '\n')
        local filename=$(basename -- "${file}")
        cn="${filename%.*}"

        curl ${caurl} --cert ${clientcert} -v -o ${tempout} --cacert ${cacert} --data-urlencode "action=enrollKey" \
        --data-urlencode "ca=${caprofile}" --data-urlencode "response.cert.format=1" --data-urlencode "request=${request}" --tlsv1.2

    done

}

make_temporary_log
main | tee -a /proc/$$/fd/3
copy_to_run_log

exit 0