#!/bin/bash

dialog                                         \
   --title 'Aguarde'                           \
   --infobox '\nIniciando a instalação, aguarde um momento...'  \
   0 0

#sleep 2
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
     Remover programa       'Desinstala o serviço OpenVPN'                    \
     Adicionar_Cliente    'Adiciona clientes a VPN já existente'               \
     Deletar_Cliente  'Deleta o cliente e suas credenciais do servidor'

}


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


if [[ ! -e /etc/openvpn/server/server.conf ]]; then
        clear
        ip=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

        if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
                echo 'to aqui'
                public_ip=$(curl -s https://api.ipify.org)
                #echo $public_ip
                #ip=$public_ip
        fi


        if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
                ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
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
        echo $client
        sleep 10

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
        if [[ -n "$ip6" ]]; then
                # Habilitando o net.ipv6.conf.all.forwarding para o sistema
                echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/30-openvpn-forward.conf
                echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
        fi

        #Serviço para as regras de iptables
        iptables_path=$(command -v iptables)
        ip6tables_path=$(command -v ip6tables)


        if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
                iptables_path=$(command -v iptables-legacy)
                ip6tables_path=$(command -v ip6tables-legacy)
        fi
        echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
                if [[ -n "$ip6" ]]; then
                        echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
                fi
                echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
                systemctl enable --now openvpn-iptables.service


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
        echo "Tratar para quando o VPN ja tiver sido instalado"


fi


