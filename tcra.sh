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
config="${__conf}""/tcra.conf"
log="${__dir}""/log/revoke-""${dtgf}"".log"
arg1=${1}
arg2=${2}
arg3=${3}


startup() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info]  Trusted Core: RA v${ver} started" >> $log
    ## CHECK AND LOAD EXTERNAL CONFIG
    if [ ! -e $config ]
    then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [error] Configuration file missing" >> $log
        exit 1
    else
        source $config
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Configuration file loaded sucessfully, ${config}" >> $log
    fi
    if [ -f $arg1 ]
    then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Input file located" >> $log
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [error] Input file missing" >> $log
        exit 1
    fi
}

gen_ecdsa() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Reading input file to memory, ${arg1}" >> $log
    local subject=$(cat ${arg1})
    local filesize=$(stat --format=%s "${arg1}")
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed reading input file, ${filesize} bytes, ${arg1}" >> $log
    echo $filesize
    local counter=0

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating private key and csr for each subject" >> $log
    for i in $subject
    do 
        echo $i
        local outputdir="${__dir}/output/${i}"
        local csr="${outputdir}/${i}.csr"
        local pkey="${outputdir}/${i}.key"
        local p7b="${outputdir}/${i}.p7b"
        local pre="-----BEGIN PKCS7-----"
        local post="-----END PKCS7-----"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Creating directory" >> $log
        mkdir ${outputdir}
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Directory created, ${outputdir}" >> $log

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating private key for ${i}" >> $log
        openssl ecparam -name secp384r1 -genkey -noout -out ${pkey}
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Private key generated, ${i}.key" >> $log

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating PKCS#10 CSR for ${i}" >> $log
        openssl req -new -key "${outputdir}/${i}.key" -nodes -out ${csr} -sha384 -subj "/CN=${i}/" -config "${__conf}/ecdsa.cnf"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] PKCS#10 CSR generated, ${i}.csr" >> $log

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating temporary files" >> $log
        local tempreq=$(mktemp /tmp/temp.XXXXXXXXX)
        local tempout=$(mktemp /tmp/temp.XXXXXXXXX)
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed generating temporary files" >> $log

        if [[ $arg3 == "sign" ]]
        then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Transmitting request to CA" >> $log
            local p10request=$(sed -e '2,$!d' -e '$d' ${csr})
            echo "action=enrollKey&ca=${ecdsaprofile}&request=${p10request}" > ${tempreq}
            curl ${caecc} --cert ${clientcert} -v -o ${tempout} --cacert ${cacert} --data-binary @${tempreq} --tlsv1.2
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Signed certificate output received from CA" >> $log
        
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Generating PKCS#7" >> $log
            echo ${pre} > ${p7b}
            tr --delete '\n' < ${tempout} | cut -c 156-  >> ${p7b}
            echo ${post} >> ${p7b}
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] PKCS#7 file generated" >> $log
        fi

        counter=$(( counter + 1 ))
    done
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [info] Completed generating ${counter} key pairs" >> $log
}

startup

if [[ $arg2 == "ecdsa" ]]
then
    gen_ecdsa
fi

if [[ $arg2 == "ecdh" ]]
then
    gen_ecdh
fi

if [[ $arg2 == "rsa" ]]
then
    gen_rsa
fi

exit 0