Vagrant.require_version '>= 1.6.0'
synced_folder="/home/vagrant/env"
Vagrant.configure('2') do |config|
    config.vm.box="ubuntu-16.04-server-amd64"
    config.vm.box_url="file://../ubuntu-16.04-server-amd64/ubuntu-16.04-server-amd64.box"
    config.vm.network "private_network", ip: "192.168.2.3"
    config.vm.synced_folder ".", "#{synced_folder}", type: "nfs"
    config.vm.provision "bashrc", type: "shell", keep_color: true, inline: %~
        (grep -q -F "cd \"#{synced_folder}\" /home/vagrant/.bashrc" || echo -e "\ncd \"#{synced_folder}\"" >> "/home/vagrant/.bashrc")
    ~
    config.vm.provision "system", type: "shell", keep_color: true, run: "always", inline: %~
        bash #{synced_folder}/install.sh
    ~
    config.ssh.insert_key = false
    config.ssh.forward_agent = true
end


