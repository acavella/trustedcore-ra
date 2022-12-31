#!/usr/bin/env bash

# NAME: tcra.sh
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
log="${__dir}""/log/revoke-""${dtgf}"".log"
start=$(date +%s)
reqs=("openssl" "curl" "sed")
arg1=${1}
arg2=${2}
arg3=${3:-default}

is_command() {
    # Checks to see if the given command (passed as a string argument) exists on the system.
    # The function returns 0 (success) if the command exists, and 1 if it doesn't.
    local check_command="$1"

    command -v "${check_command}" >/dev/null 2>&1
}

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

collect_certificate_password() {
    # Check client certificate extension
    if [[ ${clientcert} == *.p12 ]] || [[ ${clientcert} == *.pfx ]]; then
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Client certificate extension detected as PKCS#12"
        echo "Enter PKCS#12 decryption password : "
        read -s -p "Enter client certificate decryption password: " p12pw
        cert_type="p12"
    elif [[ ${clientcert} == *.pem ]]; then
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Client certificate extension detected as PEM"
        cert_type="pem"
    else 
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Unsupported certificate extension, exiting"
        exit 1
    fi
}

start() {
    # Print startup and debug information
    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Trusted Core: RA v${ver} started"
    
    # Load local configuration 
    if [ ! -e $config ]
    then
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Configuration file missing"
        exit 1
    else
        source $config
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Configuration file loaded sucessfully, ${config}"
    fi

    # Validate input file exists
    if [ -f $arg1 ]
    then
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Input file is valid"
    else
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Input file not specified or invalid"
        exit 1
    fi

    # Check for requirements, exit if not found
    for req in ${reqs[@]}; do 
        is_command ${req}
        if ( $? -eq 1 ); then
            printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Command ${req} was found"
        else
            printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Command ${req} was not found, exiting"
            exit 1
        fi
    done
}

read_input() {
    local filesize=$(stat -c %s "${arg1}")
    subject=$(cat ${arg1})
    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Completed reading input file, ${filesize} bytes, ${arg1}"
}

make_output_directory() {
    mkdir ${1}
    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Created the following directory, ${cn}"
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
        openssl req -new -key "${pkey}" -nodes -out "${csr}" -sha384 -subj "/CN=${cn}" -config "${__conf}/rsa.cnf"
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "${str}"
    elif [[ ${arg2} == "ecdsa" ]]; then
        openssl req -new -key "${pkey}" -nodes -out "${csr}" -sha384 -subj "/CN=${cn}" -config "${__conf}/ecdsa.cnf"
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "${str}"
    elif [[ ${arg2} == "ecdh" ]]; then
        openssl req -new -key "${pkey}" -nodes -out "${csr}" -sha384 -subj "/CN=${cn}" -config "${__conf}/ecdh.cnf"
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "${str}"
    else
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [error] %s\n" $(date +%s) "Unrecognized argument, ${arg2}, exiting."
        exit 1
    fi
}

generate_random_password() {
    randpass=$(openssl rand -base64 14)
    echo "${randpass}" > ${outputdir}/${cn}_pass.txt
    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Random password generated, >112bits entropy"
}

main() {
    
    start
    read_input
    local counter=0

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

    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Generating private key and csr for each subject"
    for cn in $subject; do 

        local outputdir="${__dir}/output/${cn}"
        local csr="${outputdir}/${cn}.csr"
        local pkey="${outputdir}/${cn}.key"
        local p7b="${outputdir}/${cn}.p7b"
        local p12="${outputdir}/${cn}.p12"
        local tempreq=$(mktemp /tmp/temp.XXXXXXXXX)
        local tempout=$(mktemp /tmp/temp.XXXXXXXXX)
        local pre="-----BEGIN PKCS7-----"
        local post="-----END PKCS7-----"

        make_output_directory ${outputdir}

        generate_private_key

        generate_csr

        if [[ $arg3 == "sign" ]]
        then
            printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Sending PKCS#10 request to RAMI API"
            local p10request=$(sed -e '2,$!d' -e '$d' ${csr} | tr --delete '\n')
            curl ${caurl} --cert ${clientcert} -v -o ${tempout} --cacert ${cacert} --data-urlencode "action=enrollKey" \
            --data-urlencode "ca=${caprofile}" --data-urlencode "response.cert.format=1" --data-urlencode "request=${p10request}" --tlsv1.2

            # Need logic to validate response
            printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Valid response received from RAMI API"
        
            echo -e ${pre} > ${p7b}
            tr --delete '\n' < ${tempout} | sed -n -e 's/^.*base64CertChain=//p'  | sed 's/\r$//' >> ${p7b}
            echo -e ${post} >> ${p7b}
            printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "PKCS#7 generated from RAMI response"

            generate_random_password

            local result=$(mktemp /tmp/temp.XXXXXXXXX)
            openssl pkcs7 -in ${p7b} -inform DER -out ${result} -print_certs
            openssl pkcs12 -export -inkey ${pkey} -in ${result} -out ${p12} -passout pass:${ranpass}
            rm -f ${result}
            printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "PKCS#12 generated"
        fi

        rm -f ${tempreq}
        rm -f ${tempout}
        printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Temporary files cleaned up"

        counter=$(( counter + 1 ))
    done
    end=$(date +%s)
    printf "%(%Y-%m-%dT%H:%M:%SZ)T $$ [info] %s\n" $(date +%s) "Completed generating ${counter} key pairs in $(($end-$start)) seconds"
}

make_temporary_log
main | tee -a /proc/$$/fd/3
copy_to_run_log

exit 0