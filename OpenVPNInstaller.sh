#!/bin/bash


dialog                                         \
   --title 'Aguarde'                           \
   --infobox '\nIniciando a instalação, aguarde um momento...'  \
   0 0

sleep 2
set -e

if [[ $EUID -ne 0 ]]; then
        echo "Voce deve ser administrador do sistema" 1>&2
        exit 1
fi

if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
        echo "O sistema está utilizando um kernel antigo, que é incompatível com este instalador"
        exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
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
        echo "This installer seems to be running on an unsupported distribution.
Supported distributions are Ubuntu, Debian, CentOS, and Fedora."
        exit
fi

dialog                                            \
   --title 'Sistema operacional'                             \
   --msgbox "Você está utilizando um sistema $os $os_version."  \
   6 40

start_menu () {

dialog                                       \
     --title 'Perfil'                          \
     --menu 'Escolha o que deseja fazer na instalação:'  \
     0 0 0                                     \
     Instalar_VPN       'Instala e configura o serviço VPN'                    \
     Adicionar_Cliente    'Adiciona clientes a VPN já existente'               \
     Deletar_Cliente  'Deleta o cliente e suas credenciais do servidor'

}

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

start_menu
