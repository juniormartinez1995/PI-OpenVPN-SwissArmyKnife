
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


# Checagem do sistema operacional sendo utilizado
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
        echo "Este script está rodando numa versão não suportada"
        exit
fi

dialog                                            \
   --title 'Sistema operacional'                             \
   --msgbox "Você está utilizando um sistema $os $os_version."  \
   6 40

start_menu_installed () {

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

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
        clear
        ip=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

        if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
                echo 'to aqui'
                public_ip=$(curl -s https://api.ipify.org)
        fi


        if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
                ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
        fi
        #echo $public_ip

        choice=$( dialog --stdout --menu 'Protocolo' 0 0 0 1 UDP 2 TCP)

        clear
        case $choice in
                1)
                        protocol=udp
                        ;;
                2)
                        protocol=tcp
                        ;;
        esac

        clear


        port=$( dialog --stdout --inputbox 'Porta [1194]:' 0 0 )

        if [ -z $port ]; then
                port="1194"
        fi


        dns=$( dialog --stdout --menu 'Servidor de DNS:' 0 0 0 1 "Current system resolvers" 2 Google 3 "1.1.1.1" 4 OpenDNS 5 Quad9 6 AdGuard)
        clear


fi
