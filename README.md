# suricata_config


Script to modify suricata.yaml for all sensors

sudo salt-cp '*' /root/suricata-cfg.sh /tmp/suricata-cfg.sh

￼sudo salt '*' cmd.run "bash /tmp/suricata-cfg.sh"￼￼

sudo salt '*' cmd.run "rm -f /tmp/suricata-cfg.sh"
