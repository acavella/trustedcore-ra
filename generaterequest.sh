#!/usr/bin/env bash

# NAME: signcert.sh
# DECRIPTION: Custom regsitration authority client used with ISC RAMI API
# AUTHOR: Tony Cavella (tony@cavella.com)
# SOURCE: https://github.com/acavella/trustedcore-ra

## DEBUG OPTIONS
set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

## GLOBAL VARIABLES
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



make_temporary_log() {
    # Create a random temporary file for the log
    local TEMPLOG=$(mktemp /tmp/tcra_temp.XXXXXX)
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

make_output_directory() {
    mkdir ${1}
    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Created the following directory, ${cn}"
}

generate_private_key() {
    if [[ ${arg2} == "rsa" ]]; then 
        openssl genrsa -out ${pkey} 4096
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Generated RSA private key, ${pkey}"
    elif [[ ${arg2} == "ecdsa" ]]; then
        openssl ecparam -name secp384r1 -genkey -noout -out "${pkey}"
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Generated ECC private key, ${pkey}"
    elif [[ ${arg2} == "ecdh" ]]; then
        openssl ecparam -name secp384r1 -genkey -noout -out "${pkey}"
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Generated ECC private key, ${pkey}"
    else
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Unrecognized argument, ${arg2}, exiting"
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
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Unrecognized argument, ${arg2}, exiting"
        exit 1
    fi
}

start() {
    

    # Print startup and debug information
    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Trusted Core: RA v${ver} - Generate Request"
    
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
    local start=$(date +%s) # Log start time
    local targetdir="${__dir}/output/${dtgf}"

    start 
    set_profile
    make_output_directory ${targetdir}

    for file in ${arg1}*
    do
        local request=$(sed -e '2,$!d' -e '$d' ${file} | tr --delete '\n')
        local filename=$(basename -- "${file}")
        local cn="${filename%.*}"
        local pkey="${targetdir}/${cn}.key"
                
        generate_private_key
        generate_csr

    done

}

make_temporary_log
main | tee -a /proc/$$/fd/3
copy_to_run_log

exit 0