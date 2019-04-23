#!/bin/bash


nsm_dir=/etc/nsm


function modify_suricata {
    cp $suricata_file ${suricata_file}-`date +"%Y%m%d-%H%S"`
    
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