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

## DECLARE VARIABLES
__dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
__bin="${__dir}/bin"
__conf="${__dir}/conf"
dtgf=$(date +%Y-%m-%d_%H%M)

ver=$(<VERSION)

config="${__conf}""/local.conf"
log="${__dir}""/log/tcra-""${dtgf}"".log"
reqs=("openssl" "curl" "sed")
arg1=${1}
arg2=${2:-default}
arg3=${3:-default}

is_command() {
    # Checks to see if the given command (passed as a string argument) exists on the system.
    # The function returns 0 (success) if the command exists, and 1 if it doesn't.
    local check_command="$1"

    command -v "${check_command}" >/dev/null 2>&1
}

show_ascii() {
    printf " ______             __         __  _____\n"
    printf "/_  __/_____ _____ / /____ ___/ / / ___/__  _______\n"
    printf " / / / __/ // (_-</ __/ -_) _  / / /__/ _ \/ __/ -_)\n"
    printf "/_/ /_/  \_,_/___/\__/\__/\_,_/  \___/\___/_/  \__/\n"
    printf "          Trusted Core: RA Version ${ver}\n\n"

}

load_config() {
    if [ ! -e $config ]
    then
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Configuration file missing"
        exit 1
    else
        source $config
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Configuration file loaded sucessfully, ${config}"
    fi
}

check_reqs() {
    for req in ${reqs[@]}; do
        if is_command ${req} ; then
            printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Command ${req} was found"
        else
            printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Command ${req} was not found, exiting"
            exit 1
        fi
    done
}

show_help() {
    if [[ ${arg1} = "-h" ]] || [[ ${arg1} = "--help" ]]
    then
        printf "Trusted Core: RA Version ${ver}\n\n"
        printf "Usage: vim [arguments] [file ..]       edit specified file(s)\n"
        printf "or: vim [arguments] -               read text from stdin\n"
        printf "or: vim [arguments] -t tag          edit file where tag is defined\n"
        printf "or: vim [arguments] -q [errorfile]  edit file with first error\n\n"
        printf "Arguments:\n"
        printf "-v                   Vi mode (like "vi")\n"
        printf "-e                   Ex mode (like "ex")\n\n"
        exit 0
}

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
    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Created the following directory, ${1}"
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
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [error] Unrecognized argument, ${arg2}, exiting."
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
    local start=$(date +%s) # Log start time
    local targetdir="${__dir}/output/${dtgf}"

    show_ascii
    load_config
    check_reqs
    set_profile
    read_input
    make_output_directory ${targetdir}

    for cn in $subject; do

        local pkey="${targetdir}/${cn}.key"
        local csr="${targetdir}/${cn}.csr"
                
        generate_private_key
        generate_csr

    done
}

make_temporary_log
main | tee -a /proc/$$/fd/3
copy_to_run_log

exit 0