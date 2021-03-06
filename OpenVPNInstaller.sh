#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
                dialog                                            \
   --title 'AVISO'                             \
   --msgbox "Você deve executar esse script como administrador do sistema"  \
   6 40
        exit
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
        dialog                                            \
   --title 'AVISO'                             \
   --msgbox "Este script não é compatível com o seu sistema operacional"  \
   6 40
        exit
fi

dialog                                            \
   --title 'Sistema operacional'                             \
   --msgbox "Você está utilizando um sistema $os $os_version."  \
   6 40


set_protocol () {
        if [[ "$1" = "udp" ]]; then
                echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
        fi
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

        esac

}

new_client () {
        {
        cat /etc/openvpn/server/client-common.txt
        echo "<ca>"
        cat /etc/openvpn/server/easy-rsa/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
        echo "</cert>"
        echo "<key>"
        cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
        echo "</key>"
        echo "<tls-crypt>"
        sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
        echo "</tls-crypt>"
        } > ~/"$client".ovpn
}

add_iptables_rules () {
    #Permitir conexão TCP na porta Openvpn
    iptables -A INPUT -i eth0 -m state --state NEW -p udp --dport 1194 -j ACCEPT
    #Permitir conexões da interface TUN no OpenVPN server
    iptables -A INPUT -i tun+ -j ACCEPT

    #Permitir que as conexões da interface TUN sejam encaminhadasa por meio de outras interfaces
    iptables -A FORWARD -i tun+ -j ACCEPT
    iptables -A FORWARD -i tun+ -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i eth0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

    #NAT o tráfego do cliente VPN para a internet
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

    #Se o valor padrão do OUTPUT do seu iptables não for ACCEPT, então esta linha é necessária
    iptables -A OUTPUT -o tun+ -j ACCEPT

}

remove_iptables_rules () {
    iptables -F INPUT
    iptables -F OUTPUT
    iptables -F FORWARD
    iptables -F -t filter
    iptables -F POSTROUTING -t nat
    iptables -F PREROUTING -t nat
    iptables -F OUTPUT -t nat
    iptables -F -t nat
    iptables -t nat -F
    iptables -t mangle -F
    iptables -X

    iptables -Z
    iptables -t nat -Z
    iptables -t mangle -Z

    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT

}

add_new_client () {

            client=$( dialog --stdout --inputbox 'Nome:' 0 0 )
    			
            while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
                client=$( dialog --stdout --inputbox 'Nome:' 0 0 )
            done

			cd /etc/openvpn/server/easy-rsa/
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
			new_client

            dialog                                            \
                --title 'Parabéns'                             \
                --msgbox 'Cliente adicionado com sucesso'  \
                6 40
            
            exit
}

remove_open_vpn () {
        dialog --yesno 'Deseja realmente remover o OpenVPN?' 0 0

        if [ $? = 0 ]; then
                remove_iptables_rules

                systemctl disable --now openvpn-server@server.service
                rm -rf /etc/openvpn/server
                rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
                rm -f /etc/sysctl.d/30-openvpn-forward.conf

                dialog --msgbox 'OpenVPN removido com sucesso' 5 40

                clear
                exit

        fi
}



if [[ ! -e /etc/openvpn/server/server.conf ]]; then
        clear
        ip=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

        if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
                echo 'to aqui'
                public_ip=$(curl -s https://api.ipify.org)
                #echo $public_ip
                #ip=$public_ip
        fi

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


        port=$( dialog --stdout --inputbox 'Porta [1194]:' 0 0 )

        if [ -z $port ]; then
                port="1194"
        fi
        echo "Porta escolhida: $port"

                dns=$( dialog --stdout --menu 'Servidor de DNS:' 0 0 0 1 "Current system resolvers" 2 Google 3 "1.1.1.1" 4 OpenDNS 5 Quad9 6 AdGuard)
        clear

        client=$( dialog --stdout --inputbox 'Digite o nome do cliente:' 0 0 )

        if [ -z $client ]; then
                client="client"
        fi
        #echo $client
        #sleep 10

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


        mkdir -p /etc/openvpn/server/easy-rsa/
        { wget -q0- 'https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz' 2>/dev/null || curl -sL 'https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz' ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
        chown -R root:root /etc/openvpn/server/easy-rsa/
        cd /etc/openvpn/server/easy-rsa/

        ./easyrsa init-pki
        ./easyrsa --batch build-ca nopass
        EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
        EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
        EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl


        cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
        chown nobody:"$group_name" /etc/openvpn/server/crl.pem
        chmod o+x /etc/openvpn/server/
        openvpn --genkey --secret /etc/openvpn/server/tc.key

        echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem

        #Arquivo de config do servidor
        echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf

        if [[ -z "$ip6" ]]; then
                echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
        else
                echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
                echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
        fi

        echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf

        set_dns $dns

        echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf

        set_protocol $protocol

        echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
        echo 1 > /proc/sys/net/ipv4/ip_forward

    add_iptables_rules


        [[ -n "$public_ip" ]] && ip="$public_ip"

        echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt


        systemctl enable --now openvpn-server@server.service

        new_client

else
        mChoice=$( dialog --stdout --menu 'Menu principal' 0 0 0 1 "Adicionar cliente" 2 "Remover cliente" 3 "Remover OpenVPN")

        case $mChoice in
                1)
                        add_new_client
                        ;;
                2)
                        echo "remover cliente"
                        ;;
                3)
                        remove_open_vpn
                        ;;
        esac

fi
