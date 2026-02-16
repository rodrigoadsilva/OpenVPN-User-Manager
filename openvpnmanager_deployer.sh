#!/bin/bash

set -euo pipefail

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

# Configuráveis
APP_DIR="/OpenVPN-User-Manager"
REPO_URL="https://github.com/rodrigoadsilva/OpenVPN-User-Manager.git"
SERVICE_NAME="openvpn-user-manager"
PORT=3223
GROUP_ADMIN="openvpn.admin"
GROUPS_FILE="groups.txt"
NON_INTERACTIVE=0

on_error() {
    local rc=$?
    echo -e "${RED}${ERRO} Erro no script. Saindo (codigo: $rc)${NC}"
    exit $rc
}
trap on_error ERR

log() { echo -e "${BLUE}[INFO]${NC} $*"; }
info() { echo -e "${GREEN}${SUCCESS} [OK]${NC} $*"; }
warn() { echo -e "${YELLOW}${WARNING}${WARNING} [WARN]${NC} $*"; }
error() { echo -e "${RED}${ERRO} [ERROR]${NC} $*"; }

print_banner() {
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
}

ensure_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        echo -e "${RED}${ERRO} - Por favor, execute como root${NC}"
        exit 1
    fi
}

install_deps() {
    log "Instalando dependencias..."
    apt update -y
    apt install -y git python3-pip || { echo -e "${ERRO} Erro ao instalar dependências.${NC}"; exit 1; }
    info "Dependencias instaladas"
}

install_app() {
    log "Baixando OpenVPN User Manager..."
    if [ -d "$APP_DIR/.git" ]; then
        log "Diretório $APP_DIR existe. Atualizando repo..."
        git -C "$APP_DIR" pull
    else
        mkdir -p "$APP_DIR"
        git clone "$REPO_URL" "$APP_DIR"
    fi

    log "Instalando requisitos..."
    pip3 install --break-system-packages -r "$APP_DIR/requirements.txt"
    info "Aplicação instalada em $APP_DIR"
}

configure_service() {
    log "Configurando serviço systemd..."
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=OpenVPN User Manager
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 ${APP_DIR}/main.py
Restart=on-failure
RestartSec=5
WorkingDirectory=${APP_DIR}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now ${SERVICE_NAME}
    info "Servico ${SERVICE_NAME} ativado e iniciado"
}

ensure_rc_local() {
    # Garante que /etc/rc.local exista e seja executavel
    if [ ! -f /etc/rc.local ]; then
        cat <<'EOF' > /etc/rc.local
#!/bin/sh -e
exit 0
EOF
        chmod +x /etc/rc.local
    fi
}

configure_firewall() {
    log "Configurando firewall (porta ${PORT})..."
    # Insere regra se ainda não existir
    if ! iptables -C INPUT -p tcp --dport ${PORT} -j ACCEPT 2>/dev/null; then
        iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT -m comment --comment "OpenVPN User Manager Port"
        info "Regra iptables adicionada"
    else
        info "Regra iptables ja existente"
    fi

    # Persistir via /etc/rc.local (simples) - manteve a abordagem original
    RULE_COMMENT='# Regra para permitir acesso ao OpenVPN User Manager'
    RULE="iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT -m comment --comment \"OpenVPN User Manager Port\""

    ensure_rc_local

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
        info "Regra persistida em /etc/rc.local"
    else
        info "Regra ja persistida em /etc/rc.local"
    fi
}

create_admin_group() {
    log "Criar o grupo para usuarios administradores do OpenVPN User Manager..."
    if getent group "$GROUP_ADMIN" >/dev/null; then
        info "Grupo $GROUP_ADMIN ja existe"
    else
        groupadd "$GROUP_ADMIN"
        info "Grupo $GROUP_ADMIN criado"
    fi
}

show_groups_file() {
    echo "|"
    echo "|"
    echo "|"
    echo "|"
    echo "=============================================="
    echo "Este sistema utiliza grupos para acesso do mesmo e gerenciar os usuarios de VPN."
    echo "Os usuários que terão acesso ao OpenVPN User Manager devem estar vinculados ao grupo ${GROUP_ADMIN}."
    echo "Os grupos estao listados no arquivo ${GROUPS_FILE}"
    echo "Cada grupo deve ser adicionado ao sistema para que os usuarios possam ser vinculados a eles."
    echo ""
    echo "Conteudo do arquivo ${GROUPS_FILE}:"
    if [ -f "${GROUPS_FILE}" ]; then
        cat "${GROUPS_FILE}"
    else
        echo "(arquivo ${GROUPS_FILE} nao existe)"
    fi
    echo "=============================================="
}

interactive_group_menu() {
    # Menu interativo para gerenciamento de grupos
    p=0
    while true; do
        echo "============== Ajuste de grupos ================"
        echo ""
        echo "Escolha uma das opcoes abaixo:"
        echo "1 - Adicionar um usuário ao grupo ${GROUP_ADMIN}"
        echo "2 - Limpar e usar apenas o grupo user-vpn"
        echo "3 - Limpar e adicionar grupos ao sistema"
        echo "4 - Sair"
        echo ""
        read -r -p "Digite a opcao desejada: " p

        case $p in
            1)
                read -r -p "Digite o nome do usuario: " USERNAME
                if id "$USERNAME" >/dev/null 2>&1; then
                    echo -e "${BOLD}${YELLOW}Usuario '$USERNAME' existe no sistema. Adicionando ao grupo ${GROUP_ADMIN}...${NC}"
                    usermod -aG "$GROUP_ADMIN" "$USERNAME" && info "Usuario $USERNAME adicionado ao grupo ${GROUP_ADMIN}" || error "Erro ao adicionar o usuario"
                else
                    echo -e "${YELLOW}Usuario '$USERNAME' NAO existe.${NC}"
                fi
                ;;
            2)
                echo "Resetando e adicionando grupo ao sistema..."
                echo "" > "${GROUPS_FILE}"
                if ! getent group user-vpn >/dev/null; then
                    groupadd user-vpn
                fi
                echo "user-vpn" >> "${GROUPS_FILE}"
                info "Grupo user-vpn preparado"
                ;;
            3)
                echo "Resetando e adicionando grupos ao sistema..."
                echo "" > "${GROUPS_FILE}"
                read -r -p "Digite o nome dos grupos separados por espaco (ex: financeiro-vpn comercial-vpn): " grupos
                for grupo in $grupos; do
                    if getent group "$grupo" >/dev/null; then
                        warn "Grupo $grupo ja existe"
                    else
                        groupadd "$grupo" && info "Grupo $grupo adicionado" || warn "Falha ao adicionar $grupo"
                    fi
                    echo "$grupo" >> "${GROUPS_FILE}"
                done
                ;;
            4)
                echo "Saindo do menu de grupos..."
                break
                ;;
            *)
                echo "Opcao invalida!"
                ;;
        esac
    done
}

print_final_message() {
    echo "OpenVPN User Manager instalado e iniciado com sucesso!"
    echo "Acesse via navegador: http://<IP_DO_SEU_SERVIDOR>:${PORT}"
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --non-interactive|-n)
                NON_INTERACTIVE=1
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
}

main() {
    parse_args "$@"
    print_banner
    ensure_root
    install_deps
    install_app
    configure_service
    configure_firewall
    create_admin_group
    show_groups_file

    if [ "$NON_INTERACTIVE" -eq 0 ]; then
        interactive_group_menu
    else
        log "Modo nao-interativo: pulando menu de grupos"
    fi

    print_final_message
}

main "$@"