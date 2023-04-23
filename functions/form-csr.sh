#!/usr/bin/env bash

# Display a form to collect CSR details
form_csr=$(zenity --forms --title="Certificate Signing Request" \
    --text="Enter details for CSR." \
    --separator="," \
    --add-entry="Common Name" \
    --add-entry="Organization" \
    --add-entry="City" \
    --add-entry="State" \
    --add-entry="Country" \
    --add-combo="Algorithm" \
    --combo-values="RSA|ECDSA|ECDH" \
)

# Split the response into an array
IFS=',' read -ra fields <<< "${form_csr}"

# Extract the values from the array
dn_cn=${fields[0]}
dn_org=${fields[1]}
dn_city=${fields[2]}
dn_state=${fields[3]}
dn_country=${fields[4]}
dn_algorithm=${fields[5]}
