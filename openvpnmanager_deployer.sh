#!/bin/bash

## COLORS
BOLD='\033[1m'
NC='\033[0m' # No Color
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
## ICONS
SUCCESS='\033[0;32m \xe2\x9c\x93'
ERRO='\033[0;31m \xe2\x9c\x97'
WARNING='\xe2\x9d\x97'
 
clear
echo -e "${BLUE}"
echo " ####################################"
echo " #                                  #"
echo " #  OpenVPN User Manager Installer  #"
echo " #                                  #"
echo " ####################################"
echo "By: Rodrigo Alves"
echo -e "${NC}"
echo "|"
echo "|"

if [ "$EUID" -ne 0 ]
  then echo "Por favor, execute como root"
  exit
fi

echo "Instalando dependencias..."
apt update
apt install git -y
apt install python3-pip -y
if [ $? -ne 0 ]; then
    echo "|"
    echo "|"
    echo -e "${ERRO} Erro ao instalar dependências.${NC}"
    exit 1
fi


echo -e "${YELLOW}Baixando OpenVPN User Manager...${NC}"
cd /
git clone https://github.com/rodrigoadsilva/OpenVPN-User-Manager.git
cd OpenVPN-User-Manager
echo -e "${YELLOW}Instalando requisitos...${NC}"
pip3 install -r requirements.txt

echo -e "${YELLOW}Configurando serviço...${NC}"
cat << EOF > /etc/systemd/system/openvpn-user-manager.service
[Unit]
Description=OpenVPN User Manager
After=network.target

[Service]
Type=simple

# Executar como root
User=root
Group=root

# Caminho completo para o Python e para o script
ExecStart=/usr/bin/python3 /OpenVPN-User-Manager/main.py

# Reiniciar automaticamente em caso de erro
Restart=on-failure
RestartSec=5

# Local onde o processo sera executado (opcional)
WorkingDirectory=/OpenVPN-User-Manager

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable openvpn-user-manager.service
systemctl start openvpn-user-manager.service

echo -e "${YELLOW}Configurando firewall...${NC}"
# Adiciona regra ao iptables para liberar a porta 3223
iptables -I INPUT -p tcp --dport 3223 -j ACCEPT -m comment --comment "OpenVPN User Manager Port"

# Salva as regras do iptables para que persistam após reinicialização
# Certifica-se que /etc/rc.local existe e insere a linha antes do "exit 0"
RULE_COMMENT='# Regra para permitir acesso ao OpenVPN User Manager'
RULE='iptables -I INPUT -p tcp --dport 3223 -j ACCEPT -m comment --comment "OpenVPN User Manager Port"'

# Criar /etc/rc.local padrão se não existir
if [ ! -f /etc/rc.local ]; then
  cat <<'EOF' > /etc/rc.local
#!/bin/sh -e
exit 0
EOF
  chmod +x /etc/rc.local
fi
# Insere a regra antes do "exit 0" se ainda não existir
if ! grep -Fxq "$RULE" /etc/rc.local; then
    awk -v c="$RULE_COMMENT" -v r="$RULE" '{
        if ($0 == "exit 0") {
            print c
            print r
            print $0
        } else {
            print $0
        }
    }' /etc/rc.local > /tmp/rc.local.$$ && mv /tmp/rc.local.$$ /etc/rc.local
    chmod +x /etc/rc.local
fi

echo "Criar o grupo para usuários administradores do OpenVPN User Manager..."
groupadd openvpn.admin

echo "=============================================="
echo "Este sistema utiliza grupos para acesso do mesmo e gerenciar os usuarios de VPN."
echo "Os usuários que terão acesso ao OpenVPN User Manager devem estar vinculados ao grupo openvpn.admin."
echo "Os grupos estao listados no arquivo groups.txt"
echo "Cada grupo deve ser adicionado ao sistema para que os usuarios possam ser vinculados a eles."
echo ""
echo "Conteudo do arquivo groups.txt:"
cat groups.txt
echo "=============================================="

p=0;
 
while true $p ="0";
do
   
    echo "============== Ajuste de grupos ================"
    echo ""
    echo "Escolha uma das opcoes abaixo:"
    echo "1 - Adicionar um usuário ao grupo openvpn.admin"
    echo "2 - Limpar e usar apenas o grupo user-vpn"
    echo "3 - Limpar e adicionar grupos ao sistema"
    echo "4 - Sair"
    echo ""
    echo "Digite a opcao desejada:"
    read p
 
    case $p in
        1)
        echo "Adicionando usuário ao grupo openvpn.admin..."
        echo "Digite o nome do usuário que terá acesso ao OpenVPN User Manager:"
        echo -n "Digite o nome do usuário: "
        read USERNAME
        if id "$USERNAME" >/dev/null 2>&1; then
            echo "${YELLOW}Usuário '$USERNAME' existe no sistema. Adicionando ao grupo openvpn.admin...${NC}"
            usermod -aG openvpn.admin $USERNAME
            if [ $? -eq 0 ]; then
                echo -e "${SUCCESS} Usuário $USERNAME adicionado ao grupo openvpn.admin com sucesso!${NC}"
            else
                echo -e "${ERRO} Erro ao adicionar o usuário $USERNAME ao grupo openvpn.admin.${NC}"
            fi
        else
            echo "${YELLOW}Usuário '$USERNAME' NÃO existe.${NC}"
        fi
        ;;
        2)
        echo "Resetando e adicionando grupo ao sistema..."
        echo "Removendo todos os grupos existentes..."
        echo "" > groups.txt
        echo "Adicionando grupo user-vpn..."
        groupadd user-vpn
        echo "user-vpn" >> groups.txt
        echo "Grupo adicionado com sucesso!"
        ;;
        3)
        echo "Resetando e adicionando grupo ao sistema..."
        echo "Removendo todos os grupos existentes..."
        echo "" > groups.txt
        echo "Adicionando grupo user-vpn..."
        echo "Digite o nome dos grupos separados por espaco (ex: financeiro-vpn comercial-vpn):"
        read grupos
        for grupo in $grupos
        do
            echo "Adicionando grupo: $grupo"
            groupadd $grupo
            echo $grupo >> groups.txt
        done
        echo "Grupos adicionados com sucesso!"
        ;;
        4)
        echo "Saindo..."
        exit 0
        ;;
        *)
        echo "Opcao invalida!"
        ;;
    esac
done

echo "OpenVPN User Manager instalado e iniciado com sucesso!"
echo "Acesse via navegador: http://<IP_DO_SEU_SERVIDOR>:3223"