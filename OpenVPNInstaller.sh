
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

set_dns () {
        case "$1" in
        1|"")
		if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
			resolv_conf="/run/systemd/resolve/resolv.conf"
		else
			resolv_conf="/etc/resolv.conf"
		fi
		
		grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
		done
		;;

        2)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
	;;
	3)
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
	;;
	4)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
	;;
	5)
		echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
	;;
	6)
		echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
	;;

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
        dialog --yesno 'Deseja começar a instalação?' 0 0


        if [[ "os" = "ubuntu" || "os" = "debian" ]]; then
                firewall="iptables"
        fi

        if [ $? = 0 ]; then
                if [[ "$os" = "ubuntu" || "os" = "debian" ]]; then
                        clear
                        apt-get update
                        apt-get install -y openvpn openssl ca-certificates $firewall
                fi
        else
                clear
                exit
        fi



fi
