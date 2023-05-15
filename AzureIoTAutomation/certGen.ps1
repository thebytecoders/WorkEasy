#Set-PSDebug -Trace 3 # Set trace on
#set -o errexit # Exit if command failed
#set -o pipefail # Exit if pipe failed

$root_ca_dir='.'
$home_dir='.'
$algorithm='genrsa'
$COUNTRY='US'
$STATE='WA'
$LOCALITY='Redmond'
$ORGANIZATION_NAME='My Organization'
$root_ca_password='1234'
$key_bits_length='4096'
$days_till_expire=30
$ca_chain_prefix='azure-iot-test-only.chain.ca'
$intermediate_ca_dir='.'
$openssl_root_config_file='.\openssl_root_ca.cnf'
$openssl_intermediate_config_file='.\openssl_device_intermediate_ca.cnf'
$intermediate_ca_password='1234'
$root_ca_prefix='azure-iot-test-only.root.ca'
$intermediate_ca_prefix='azure-iot-test-only.intermediate'

function makeCNsubject($cn)
{
    $result="/CN=$cn"
    return $result
}

###############################################################################
# Generate Root CA Cert
###############################################################################
function generate_root_ca
{
    $common_name="Azure IoT Hub CA Cert Test Only"

    cd $home_dir
    Write-Host "Creating the Root CA Private Key`n-----------------------------------"
    openssl $algorithm -aes256 -passout pass:$root_ca_password  -out "$root_ca_dir\private\$root_ca_prefix.key.pem" $key_bits_length
	if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}

    echo "Creating the Root CA Certificate`n-----------------------------------"
    openssl req -new -x509 -config $openssl_root_config_file -passin pass:$root_ca_password -key "$root_ca_dir\private\$root_ca_prefix.key.pem" -subj (makeCNsubject $common_name) -days $days_till_expire -sha256 -extensions v3_ca -out "$root_ca_dir\certs\$root_ca_prefix.cert.pem"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}

    Write-Host "CA Root Certificate Generated At:`n---------------------------------`n    $root_ca_dir\certs\$root_ca_prefix.cert.pem`n"
    openssl x509 -noout -text -in "$root_ca_dir\certs\$root_ca_prefix.cert.pem"
	
}


###############################################################################
# Generate Intermediate CA Cert
###############################################################################
function generate_intermediate_ca
{
    $common_name="Azure IoT Hub Intermediate Cert Test Only"
    Write-Host "Creating the Intermediate Device CA`n-----------------------------------"
    cd $home_dir

    openssl $algorithm -aes256 -passout pass:$intermediate_ca_password -out "$intermediate_ca_dir\private\$intermediate_ca_prefix.key.pem" $key_bits_length
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}

    Write-Host "Creating the Intermediate Device CA CSR`n-----------------------------------"
    openssl req -new -sha256 -passin pass:$intermediate_ca_password -config $openssl_intermediate_config_file -subj (makeCNsubject $common_name) -key "$intermediate_ca_dir\private\$intermediate_ca_prefix.key.pem" -out "$intermediate_ca_dir\csr\$intermediate_ca_prefix.csr.pem"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}

    Write-Host "Signing the Intermediate Certificate with Root CA Cert`n-----------------------------------"
    openssl ca -batch -config $openssl_root_config_file -passin pass:$root_ca_password -extensions v3_intermediate_ca -days $days_till_expire -notext -md sha256 -in "$intermediate_ca_dir\csr\$intermediate_ca_prefix.csr.pem" -out "$intermediate_ca_dir\certs\$intermediate_ca_prefix.cert.pem"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}

    Write-Host "Verify signature of the Intermediate Device Certificate with Root CA`n-----------------------------------"
    openssl verify -CAfile "$root_ca_dir\certs\$root_ca_prefix.cert.pem" "$intermediate_ca_dir\certs\$intermediate_ca_prefix.cert.pem"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}

    Write-Host "Intermediate CA Certificate Generated At:`n-----------------------------------`n    $intermediate_ca_dir\certs\$intermediate_ca_prefix.cert.pem`n"
    openssl x509 -noout -text -in "$intermediate_ca_dir\certs\$intermediate_ca_prefix.cert.pem"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}

    Write-Host "Create Root + Intermediate CA Chain Certificate`n-----------------------------------"
    Get-Content "$intermediate_ca_dir\certs\$intermediate_ca_prefix.cert.pem","$root_ca_dir\certs\$root_ca_prefix.cert.pem" | Out-File -Encoding ascii "$intermediate_ca_dir\certs\$ca_chain_prefix.cert.pem"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}

    Write-Host "Root + Intermediate CA Chain Certificate Generated At:`n-----------------------------------`n    $intermediate_ca_dir\certs\$ca_chain_prefix.cert.pem"
}

###############################################################################
# Generate a Certificate for a device using specific openssl extension and
# signed with either the root or intermediate cert.
###############################################################################
function generate_device_certificate_common($cn, $dp, $cd, $cp, $ocf, $oce, $ctd)
{
    $common_name=$cn
    $device_prefix=$dp
    $certificate_dir=$cd
    $ca_password=$cp
    $server_pfx_password="1234"
    $openssl_config_file=$ocf
    $openssl_config_extension=$oce
    $cert_type_diagnostic=$ctd

    Write-Host "Creating $cert_type_diagnostic Certificate`n----------------------------------------"
    cd $home_dir

    openssl $algorithm -out "$certificate_dir\private\$device_prefix.key.pem" $key_bits_length
	if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}

    Write-Host "Create the $cert_type_diagnostic Certificate Request`n----------------------------------------"
    openssl req -config $openssl_config_file -key "$certificate_dir\private\$device_prefix.key.pem" -subj (makeCNsubject $common_name) -new -sha256 -out "$certificate_dir\csr\$device_prefix.csr.pem"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}

    openssl ca -batch -config $openssl_config_file -passin pass:$ca_password -extensions $openssl_config_extension -days $days_till_expire -notext -md sha256 -in "$certificate_dir\csr\$device_prefix.csr.pem" -out "$certificate_dir\certs\$device_prefix.cert.pem"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}


    Write-Host "Verify signature of the $cert_type_diagnostic" " certificate with the signer`n-----------------------------------"
    openssl verify -CAfile "$certificate_dir\certs\$ca_chain_prefix.cert.pem" "$certificate_dir\certs\$device_prefix.cert.pem"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}

    Write-Host "$cert_type_diagnostic Certificate Generated At:`n----------------------------------------`n    $certificate_dir\certs\$device_prefix.cert.pem`n"
    openssl x509 -noout -text -in "$certificate_dir\certs\$device_prefix.cert.pem"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}
    Write-Host "Create the $cert_type_diagnostic PFX Certificate`n----------------------------------------"
    openssl pkcs12 -in "$certificate_dir\certs\$device_prefix.cert.pem" -inkey "$certificate_dir\private\$device_prefix.key.pem" -password pass:$server_pfx_password -export -out "$certificate_dir\certs\$device_prefix.cert.pfx"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}
    Write-Host "$cert_type_diagnostic PFX Certificate Generated At:`n--------------------------------------------`n    $certificate_dir\certs\$device_prefix.cert.pfx"
    if (!$?) {
		Write-host "Error occurred"
		Read-Host "Press any key to exit"
		exit
	}
}

###############################################################################
# Generate a certificate for a leaf device
# signed with either the root or intermediate cert.
###############################################################################
function generate_leaf_certificate($cn, $dp, $cd, $cp, $ocf)
{
    $common_name=$cn
    $device_prefix=$dp
    $certificate_dir=$cd
    $ca_password=$cp
    $openssl_config_file=$ocf

    generate_device_certificate_common $common_name $device_prefix $certificate_dir $ca_password $openssl_config_file "usr_cert" "Leaf Device"
}

###############################################################################
#  Creates required directories and removes left over cert files.
#  Run prior to creating Root CA; after that these files need to persist.
###############################################################################
function prepare_filesystem
{
	if (!(Test-Path $openssl_root_config_file)) {
		Write-Host "Missing file $openssl_root_config_file"
		Read-Host "Press any key to exit"
        exit 1
	}
	if (!(Test-Path $openssl_intermediate_config_file)) {
		Write-Host "Missing file $openssl_intermediate_config_file"
		Read-Host "Press any key to exit"
        exit 1
	}

    Remove-Item csr -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item private -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item certs -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item intermediateCerts -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item newcerts -Recurse -Force -ErrorAction SilentlyContinue

    New-Item csr -ItemType Directory
    New-Item private -ItemType Directory
    New-Item certs -ItemType Directory
    New-Item intermediateCerts -ItemType Directory
    New-Item newcerts -ItemType Directory

    Remove-Item .\index.txt -Recurse -Force -ErrorAction SilentlyContinue
    New-Item .\index.txt  -ItemType File

    Remove-Item .\serial -Recurse -Force -ErrorAction SilentlyContinue
	echo 01 | Out-File -Encoding ascii serial
}

###############################################################################
# Generates a root and intermediate certificate for CA certs.
###############################################################################
function initial_cert_generation
{
    prepare_filesystem
    generate_root_ca
}

###############################################################################
# Generates a certificate for verification, chained directly to the root.
###############################################################################
function generate_verification_certificate($sn)
{
	if([string]::IsNullOrEmpty($sn)) {
		Write-Host "Usage: create_verification_certificate <subjectName>"
		Read-Host "Press any key to exit"
        exit 1
	}

    Remove-Item .\private\verification-code.key.pem  -Force -ErrorAction SilentlyContinue
    Remove-Item .\certs\verification-code.cert.pem  -Force -ErrorAction SilentlyContinue
    generate_leaf_certificate $sn "verification-code" $root_ca_dir $root_ca_password $openssl_root_config_file
}

###############################################################################
# Generates a certificate for a device, chained directly to the root.
###############################################################################
function generate_device_certificate($sn,$dcn)
{
	if([string]::IsNullOrEmpty($sn)) {
		Write-Host "Usage: create_device_certificate <subjectName>"
		Read-Host "Press any key to exit"
        exit 1
	}

    Remove-Item .\private\new-device.key.pem -Force -ErrorAction SilentlyContinue
    Remove-Item .\certs\new-device.key.pem -Force -ErrorAction SilentlyContinue
    Remove-Item .\certs\new-device-full-chain.cert.pem -Force -ErrorAction SilentlyContinue
    generate_leaf_certificate $sn $dcn $root_ca_dir $root_ca_password $openssl_root_config_file
}


###############################################################################
# Generates a certificate for a device, chained to the intermediate.
###############################################################################
function generate_device_certificate_from_intermediate($sn)
{
	if([string]::IsNullOrEmpty($sn)) {
		Write-Host "Usage: create_device_certificate_from_intermediate <subjectName>"
		Read-Host "Press any key to exit"
        exit 1
	}

    Remove-Item .\private\new-device.key.pem -Force -ErrorAction SilentlyContinue
    Remove-Item .\certs\new-device.key.pem -Force -ErrorAction SilentlyContinue
    Remove-Item .\certs\new-device-full-chain.cert.pem -Force -ErrorAction SilentlyContinue
    generate_leaf_certificate "${1}" "new-device" $intermediate_ca_dir $intermediate_ca_password $openssl_intermediate_config_file
}


###############################################################################
# Generates a certificate for a Edge device, chained to the intermediate.
###############################################################################
function generate_edge_device_certificate($sn)
{
    $device_prefix="new-edge-device"
	if([string]::IsNullOrEmpty($sn)) {
		Write-Host "Usage: create_edge_device_certificate <subjectName>"
		Read-Host "Press any key to exit"
        exit 1
	}

    Remove-Item .\private\new-edge-device.key.pem -Force -ErrorAction SilentlyContinue
    Remove-Item .\certs\new-edge-device.cert.pem -Force -ErrorAction SilentlyContinue
    Remove-Item .\certs\new-edge-device-full-chain.cert.pem -Force -ErrorAction SilentlyContinue

    # Note: Appending a '.ca' to the common name is useful in situations
    # where a user names their hostname as the edge device name.
    # By doing so we avoid TLS validation errors where we have a server or
    # client certificate where the hostname is used as the common name
    # which essentially results in "loop" for validation purposes.
    generate_device_certificate_common "$sn.ca" $device_prefix $intermediate_ca_dir $intermediate_ca_password $openssl_intermediate_config_file "v3_intermediate_ca" "Edge Device"
}

#Set-PSDebug -Off
#Set-PSDebug -Trace 0

if($args[0] -eq 'create_root_certificate') {
	initial_cert_generation
} elseif($args[0] -eq 'create_intermediate_certificate') {
	generate_intermediate_ca
} elseif($args[0] -eq 'create_verification_certificate') {
	generate_verification_certificate $args[1]
} elseif($args[0] -eq 'create_device_certificate') {
	generate_device_certificate $args[1] $args[2]
} elseif($args[0] -eq 'create_device_certificate_from_intermediate') {
	generate_device_certificate_from_intermediate $args[1]
} elseif($args[0] -eq 'create_edge_device_certificate') {
	generate_edge_device_certificate $args[1]
} else {
	Write-Host "Usage: create_root_and_intermediate                               # Creates a new root and intermediate certificates"
    Write-Host "       create_verification_certificate <subjectName>              # Creates a verification certificate, signed with <subjectName>"
    Write-Host "       create_device_certificate <subjectName>                    # Creates a device certificate signed by root with <subjectName>"
    Write-Host "       create_device_certificate_from_intermediate <subjectName>  # Creates a device certificate signed by intermediate with <subjectName>"
    Write-Host "       create_edge_device_certificate <subjectName>               # Creates an edge device certificate, signed with <subjectName>"
	Read-Host "Press any key to exit"
    #exit 1
}
