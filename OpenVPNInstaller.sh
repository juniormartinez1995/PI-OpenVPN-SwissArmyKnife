
#!/bin/bash

set -e

if [[ $EUID -ne 0 ]]; then
        echo "Voce deve ser administrador do sistema" 1>&2
        exit 1
fi

if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
        echo "O sistema está utilizando um kernel antigo, que é incompatível com este instalador"
        exit
fi

#Checagem de qual distribuição do linux que está sendo utilizada para rodar o script
if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
        group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
        os="debian"
        os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
        group_name="nogroup"
elif [[ -e /etc/centos-release ]]; then
        os="centos"
        os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
        group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
        os="fedora"
        os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
        group_name="nobody"
else
        echo "A distribuição do linux que está executando este instalador não é suportada. Apenas Ubuntu, Debian, CentOS e Fedora"
        exit
fi

echo "Sistema utilizado é o $os $os_version"


add_new_cliente () {
        {
                cat /etc/openvpn/server/cliente-common.txt
                echo "<ca>"
                cat /etc/openvpn/server/easy-rsa/pki/ca.crt
                echo "</ca>"
                echo "<cert>"
                sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$cliente".crt
                echo "</cert>"
                echo "<key>"
                cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
                echo "</key>"
                echo "tls-crypt>"
                sed -ne '/BEGIN OpenVPN Static Key/,$ p' /etc/openvpn/server/tc.key
                echo "</tls-crypt>"
        } > ~/"client".ovpn

}

