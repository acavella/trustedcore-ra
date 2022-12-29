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

start() {
    # Print startup and debug information
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info]  Trusted Core: RA v${ver} started"

    # Load local configuration 
    if [ ! -e $config ]
    then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [error] Configuration file missing"
        exit 1
    else
        source $config
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Configuration file loaded sucessfully, ${config}"
    fi

    # Validate input file exists
    if [ -f $arg1 ]
    then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Input file located"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [error] Input file missing"
        exit 1
    fi

    # Check for requirements, exit if not found
    for req in ${reqs[@]}; do 
        is_command ${req}
        if ( $? -eq 1 ); then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Command ${req} was found"
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [error] Command ${req} was not found, exiting"
            exit 1
        fi
    done
}

read_input() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Reading input file to memory, ${arg1}"
    local filesize=$(stat -c %s "${arg1}")
    subject=$(cat ${arg1})
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed reading input file, ${filesize} bytes, ${arg1}"
}

make_output_directory() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Creating output directory"
    mkdir ${1}
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Directory created, ${1}"
}

generate_private_key() {
    if [[ ${arg2} == "rsa" ]]; then 
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating private key for ${cn}"
        openssl genrsa -out ${pkey} 3072
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Private key generated, ${pkey}"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating private key for ${cn}"
        openssl ecparam -name secp384r1 -genkey -noout -out ${pkey}
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Private key generated, ${pkey}"
    fi
}

generate_csr() { }

sign_public_certificate() { }


main() {
    
    start
    read_input

    local counter=0

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating private key and csr for each subject"
    for i in $subject; do 

        local cn="${i}"
        local outputdir="${__dir}/output/${i}"
        local csr="${outputdir}/${i}.csr"
        local pkey="${outputdir}/${i}.key"
        local p7b="${outputdir}/${i}.p7b"
        local p12="${outputdir}/${i}.p12"
        local pre="-----BEGIN PKCS7-----"
        local post="-----END PKCS7-----"

        make_output_directory ${outputdir}

        generate_private_key

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating PKCS#10 CSR for ${i}" | tee ${log}
        openssl req -new -key "${outputdir}/${i}.key" -nodes -out ${csr} -sha384 -subj "/CN=${i}" -config "${__conf}/ecdsa.cnf"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] PKCS#10 CSR generated, ${i}.csr" | tee ${log}

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating temporary files" | tee ${log}
        local tempreq=$(mktemp /tmp/temp.XXXXXXXXX)
        local tempout=$(mktemp /tmp/temp.XXXXXXXXX)
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed generating temporary files" | tee ${log}

        if [[ $arg3 == "sign" ]]
        then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Transmitting request to CA" | tee ${log}
            local p10request=$(sed -e '2,$!d' -e '$d' ${csr})
            echo "action=enrollKey&ca=${ecdsaprofile}&request=${p10request}" > ${tempreq}
            curl ${caecc} --cert ${clientcert} -v -o ${tempout} --cacert ${cacert} --data-binary @${tempreq} --tlsv1.2
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Signed certificate output received from CA" | tee ${log}
        
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating PKCS#7" | tee ${log}
            echo -e ${pre} > ${p7b}
            tr --delete '\n' < ${tempout} | sed -n -e 's/^.*base64CertChain=//p'  | sed 's/\r$//' >> ${p7b}
            echo -e ${post} >> ${p7b}
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] PKCS#7 file generated" | tee ${log}

            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating random password, >112bits" | tee ${log}
            local ranpass=$(openssl rand -base64 14)
            echo ${ranpass} > ${outputdir}/${i}_pass.txt
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Random password generated" | tee ${log}

            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating PKCS#12" | tee ${log}
            local result=$(mktemp /tmp/temp.XXXXXXXXX)
            openssl pkcs7 -in ${p7b} -inform DER -out ${result} -print_certs
            openssl pkcs12 -export -inkey ${pkey} -in ${result} -out ${p12} -passout pass:${ranpass}
            rm -f ${result}
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] PKCS#7 file generated" | tee ${log}
        fi

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Cleanup temporary files" | tee ${log}
        rm -f ${tempreq}
        rm -f ${tempout}
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed temporary file cleanup" | tee ${log}

        counter=$(( counter + 1 ))
    done
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed generating ${counter} key pairs" | tee ${log}
}

gen_ecdh() {
    local counter=0

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating private key and csr for each subject" | tee ${log}
    for i in $subject
    do 
        local outputdir="${__dir}/output/${i}"
        local csr="${outputdir}/${i}.csr"
        local pkey="${outputdir}/${i}.key"
        local p7b="${outputdir}/${i}.p7b"
        local p12="${outputdir}/${i}.p12"
        local pre="-----BEGIN PKCS7-----"
        local post="-----END PKCS7-----"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Creating directory" | tee ${log}
        mkdir ${outputdir}
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Directory created, ${outputdir}" | tee ${log}

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating private key for ${i}" | tee ${log}
        openssl ecparam -name secp384r1 -genkey -noout -out ${pkey}
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Private key generated, ${i}.key" | tee ${log}

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating PKCS#10 CSR for ${i}" | tee ${log}
        openssl req -new -key "${outputdir}/${i}.key" -nodes -out ${csr} -sha384 -subj "/CN=${i}" -config "${__conf}/ecdh.cnf"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] PKCS#10 CSR generated, ${i}.csr" | tee ${log}

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating temporary files" | tee ${log}
        local tempreq=$(mktemp /tmp/temp.XXXXXXXXX)
        local tempout=$(mktemp /tmp/temp.XXXXXXXXX)
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed generating temporary files" | tee ${log}

        if [[ $arg3 == "sign" ]]
        then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Transmitting request to CA" | tee ${log}
            local p10request=$(sed -e '2,$!d' -e '$d' ${csr})
            echo "action=enrollKey&ca=${ecdsaprofile}&request=${p10request}" > ${tempreq}
            curl ${caecc} --cert ${clientcert} -v -o ${tempout} --cacert ${cacert} --data-binary @${tempreq} --tlsv1.2
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Signed certificate output received from CA" | tee ${log}
        
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating PKCS#7" | tee ${log}
            echo -e ${pre} > ${p7b}
            tr --delete '\n' < ${tempout} | sed -n -e 's/^.*base64CertChain=//p'  | sed 's/\r$//' >> ${p7b}
            echo -e ${post} >> ${p7b}
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] PKCS#7 file generated" | tee ${log}

            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating random password, >112bits" | tee ${log}
            local ranpass=$(openssl rand -base64 14)
            echo ${ranpass} > ${outputdir}/${i}_pass.txt
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Random password generated" | tee ${log}

            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating PKCS#12" | tee ${log}
            local result=$(mktemp /tmp/temp.XXXXXXXXX)
            openssl pkcs7 -in ${p7b} -inform DER -out ${result} -print_certs
            openssl pkcs12 -export -inkey ${pkey} -in ${result} -out ${p12} -passout pass:${ranpass}
            rm -f ${result}
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] PKCS#7 file generated" | tee ${log}
        fi

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Cleanup temporary files" | tee ${log}
        rm -f ${tempreq}
        rm -f ${tempout}
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed temporary file cleanup" | tee ${log}

        counter=$(( counter + 1 ))
    done
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed generating ${counter} key pairs" | tee ${log}
}

gen_rsa() {
    local counter=0

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating private key and csr for each subject" | tee ${log}
    for i in $subject
    do 
        local outputdir="${__dir}/output/${i}"
        local csr="${outputdir}/${i}.csr"
        local pkey="${outputdir}/${i}.key"
        local p7b="${outputdir}/${i}.p7b"
        local p12="${outputdir}/${i}.p12"
        local pre="-----BEGIN PKCS7-----"
        local post="-----END PKCS7-----"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Creating directory" | tee ${log}
        mkdir ${outputdir}
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Directory created, ${outputdir}" | tee ${log}

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating private key and csr for ${i}" | tee ${log}
        openssl req -new -newkey rsa:4096 -nodes -keyout ${pkey} -out ${csr} -sha384 -subj "/CN=${i}" -config "${__conf}/rsa.cnf"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Key and CSR generated for, ${i}" | tee ${log}

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating temporary files" | tee ${log}
        local tempreq=$(mktemp /tmp/temp.XXXXXXXXX)
        local tempout=$(mktemp /tmp/temp.XXXXXXXXX)
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed generating temporary files" | tee ${log}

        if [[ $arg3 == "sign" ]]
        then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Transmitting request to CA" | tee ${log}
            local p10request=$(sed -e '2,$!d' -e '$d' ${csr} | tr --delete '\n')
            curl ${carsa} --cert ${clientcert} -v -o ${tempout} --cacert ${cacert} --data-urlencode "action=enrollKey" --data-urlencode "ca=${rsaprofile}" --data-urlencode "response.cert.format=1" --data-urlencode "request=${p10request}" --tlsv1.2
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Signed certificate output received from CA" | tee ${log}
        
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating PKCS#7" | tee ${log}
            echo -e ${pre} > ${p7b}
            tr --delete '\n' < ${tempout} | sed -n -e 's/^.*base64CertChain=//p'  | sed 's/\r$//' >> ${p7b}
            echo -e ${post} >> ${p7b}
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] PKCS#7 file generated" | tee ${log}

            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating random password, >112bits" | tee ${log}
            local ranpass=$(openssl rand -base64 14)
            echo ${ranpass} > ${outputdir}/${i}_pass.txt
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Random password generated" | tee ${log}

            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating PKCS#12" | tee ${log}
            local result=$(mktemp /tmp/temp.XXXXXXXXX)
            openssl pkcs7 -in ${p7b} -inform DER -out ${result} -print_certs
            openssl pkcs12 -export -inkey ${pkey} -in ${result} -out ${p12} -passout pass:${ranpass}
            rm -f ${result}
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] PKCS#7 file generated" | tee ${log}
        fi

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Cleanup temporary files" | tee ${log}
        rm -f ${tempreq}
        rm -f ${tempout}
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed temporary file cleanup" | tee ${log}

        counter=$(( counter + 1 ))
    done
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed generating ${counter} key pairs" | tee ${log}
}

case ${arg2} in
    
    ecdsa)
    gen_ecdsa;;

    ecdh)
    gen_ecdh;;

    rsa)
    gen_rsa;;

    *)
    display_help
    exit 1;;
esac

end=$(date +%s)
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Operations completed in $(($end-$start)) seconds..." | tee ${log}

make_temporary_log
main | tee -a /proc/$$/fd/3
copy_to_run_log

exit 0