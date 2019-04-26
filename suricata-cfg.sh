#!/bin/bash


nsm_dir=/etc/nsm
suricata_vars_file=/tmp/suricata_vars.yaml

function usage {
echo "Usage:
$suricata_vars_file must exist containing the vars section of suricata.yaml to by applied"
echo '        
### example ###
vars:
  # more specific is better for alert accuracy and performance
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    #HOME_NET: "[192.168.0.0/16]"
    #HOME_NET: "[10.0.0.0/8]"
    #HOME_NET: "[172.16.0.0/12]"
    #HOME_NET: "any"

    #EXTERNAL_NET: "!$HOME_NET"
    EXTERNAL_NET: "!$HOME_NET"

    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21'
}

function modify_suricata {
    cp $suricata_file ${suricata_file}-`date +"%Y%m%d-%H%S"`
    
    lead='## Step 1: inform Suricata about your network'
    tail='## Step 2: select outputs to enable'
    sed -e "/$lead/,/$tail/{ /$lead/{N;N;p; r $suricata_vars_file
            }; s/$tail/\n\n##\n$tail/p; d }" -i $suricata_file
     
    sed -e '/- eve-log:/!b' -e ':a' \
        -e "s/\(enabled:\).*/\1 yes/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    sed -e '/- eve-log:/!b' -e ':a' \
        -e "s/\(filename:\).*/\1 eve-\%Y-\%m-\%d-\%H:\%M:\%S\.json/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file 
    
    grep -q "rotate-interval" $suricata_file || \
        sed -e '/filename: eve-.*\.json$/a \      rotate-interval: 30m' -i $suricata_file
    
    sed -e '/- eve-log:/!b' -e ':a' \
        -e "s/\(community-id:\).*/\1 true/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    sed -e '/xff:/!b' -e ':a' \
        -e "s/\(enabled:\).*/\1 yes/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    sed -e '/- alert:/!b' -e ':a' \
        -e "s/\# \(payload:\).*/\1 yes/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    sed -e '/- alert:/!b' -e ':a' \
        -e "s/\# \(payload-printable:\).*/\1 yes/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    sed -e '/- alert:/!b' -e ':a' \
        -e "s/\# \(http-body-printable:\).*/\1 yes/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    sed -e '/- alert:/!b' -e ':a' \
        -e "s/\# \(metadata:\).*/\1 yes/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    sed -e '/- alert:/!b' -e ':a' \
        -e "s/\# \(tagged-packets:\).*/\1 yes/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    sed -e '/- files:/!b' -e ':a' \
        -e "s/\(force-magic:\).*/\1 yes/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    
    sed -e "s/\#\(- dnp3\).*/\1/" -i $suricata_file
    sed -e "s/\#\(- nfs\).*/\1/" -i $suricata_file
    sed -e "s/\#\(- smb\).*/\1/" -i $suricata_file
    sed -e "s/\#\(- tftp\).*/\1/" -i $suricata_file
    sed -e "s/\#\(- ikev2\).*/\1/" -i $suricata_file
    sed -e "s/\#\(- krb5\).*/\1/" -i $suricata_file
    
    
    sed -e '/- dhcp:/!b' -e ':a' \
        -e "s/\(enabled:\).*/\1 yes/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    sed -e '/- dhcp:/!b' -e ':a' \
        -e "s/\(extended:\).*/\1 yes/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file

    sed -e '/- stats:/!b' -e ':a' \
        -e "s/#*\(\s*- stats:\).*/\1/;t trail" \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file    
	
    sed -e '/- stats:/!b' -e ':a' \
        -e 's/#*\(\s*totals:\).*/\1 yes/;t trail' \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    sed -e '/- stats:/!b' -e ':a' \
        -e 's/#*\(\s*threads:\).*/\1 7/;t trail' \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file
    
    sed -e '/- stats:/!b' -e ':a' \
        -e 's/#*\(\s*deltas:\).*/\1 no/;t trail' \
        -e 'n;ba' -e ':trail' -e 'n;btrail' -i $suricata_file

}



if [[ ! -e $suricata_vars_file ]]
  usage
  exit
fi

while IFS= read -r line ;do
    worker=`echo $line | cut -d' ' -f 1`
    [[ $worker =~ ^\# || $worker =~ master ]] && continue
	if [[ -d ${nsm_dir}/${worker} ]] ;then
        suricata_file="${nsm_dir}/${worker}/suricata.yaml" 
        echo $suricata_file
        modify_suricata
	else
	    continue
	fi
done < ${nsm_dir}/sensortab

nsm --sensor --restart