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

# Forçar modo não-interativo do APT para evitar prompts de configuração/reinício
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

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
    # use apt-get com opções para evitar prompts de configuração e reinício de serviços
    apt-get update -y
    apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        install --no-install-recommends git python3-pip python3-venv || { echo -e "${ERRO} Erro ao instalar dependências.${NC}"; exit 1; }
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

    # Criar virtualenv (venv) e instalar pacotes no venv
    log "Preparando virtualenv em ${APP_DIR}/venv..."
    if [ ! -d "${APP_DIR}/venv" ]; then
        python3 -m venv "${APP_DIR}/venv" || { echo -e "${ERRO} Falha ao criar venv.${NC}"; exit 1; }
        info "Virtualenv criado"
    else
        log "Virtualenv ja existe, atualizando pip se necessario..."
    fi

    VENV_PY="${APP_DIR}/venv/bin/python"
    VENV_PIP="${APP_DIR}/venv/bin/pip"

    # Garantir pip/packaging atualizados no venv
    "${VENV_PY}" -m pip install --upgrade pip setuptools wheel >/dev/null || { echo -e "${ERRO} Erro ao atualizar pip no venv.${NC}"; exit 1; }

    log "Instalando requisitos..."
    if [ -f "$APP_DIR/requirements.txt" ]; then
        # Instala dentro do venv
        "${VENV_PIP}" install --no-cache-dir -r "$APP_DIR/requirements.txt" || { echo -e "${ERRO} Erro ao instalar requisitos Python no venv.${NC}"; exit 1; }
    else
        warn "Arquivo de requirements nao encontrado em $APP_DIR, pulando instalacao de pacotes Python"
    fi
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
ExecStart=${APP_DIR}/venv/bin/python ${APP_DIR}/main.py
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
    echo -e "${YELLOW}=============================================="
    echo "Este sistema utiliza grupos para acesso do mesmo e gerenciar os usuarios de VPN."
    echo "Os usuários que terão acesso ao OpenVPN User Manager devem estar vinculados ao grupo ${GROUP_ADMIN}."
    echo "Os grupos estao listados no arquivo ${GROUPS_FILE}"
    echo "Cada grupo deve ser adicionado ao sistema para que os usuarios possam ser vinculados a eles."
    echo ""
    echo "Conteudo do arquivo ${GROUPS_FILE}:"
    if [ -f "${APP_DIR}/${GROUPS_FILE}" ]; then
        cat "${APP_DIR}/${GROUPS_FILE}"
    else
        echo "(arquivo ${APP_DIR}/${GROUPS_FILE} nao existe)"
    fi
    echo -e "${YELLOW}============================================== ${NC}"
}

interactive_group_menu() {
    systemctl stop ${SERVICE_NAME}
    # Menu interativo para gerenciamento de grupos
    p=0
    while true; do
        echo "|"
        echo "|"
        echo "============== Ajuste de grupos ================"
        echo ""
        echo "Escolha uma das opcoes abaixo:"
        echo "1 - Adicionar um usuário ao grupo ${GROUP_ADMIN}"
        echo "2 - Limpar o arquivo de grupos e usar apenas o grupo user.vpn"
        echo "3 - Limpar o arquivo de grupos e adicionar grupos ao sistema"
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
                    echo -n "Deseja criar o usuario '$USERNAME' e adiciona-lo ao grupo ${GROUP_ADMIN}? (s/n): "
                    read -r resposta
                    if [[ "$resposta" =~ ^[Ss]$ ]]; then
                        if useradd -m "$USERNAME"; then
                            info "Usuario $USERNAME criado"
                            # Define a senha solicitada (Mudar@123)
                            printf '%s:%s\n' "$USERNAME" 'Mudar@123' | chpasswd && info "Senha definida para $USERNAME" || error "Erro ao definir senha para $USERNAME"
                        else
                            error "Erro ao criar o usuario"
                            continue
                        fi
                        usermod -aG "$GROUP_ADMIN" "$USERNAME" && info "Usuario $USERNAME adicionado ao grupo ${GROUP_ADMIN}" || error "Erro ao adicionar o usuario"
                    else
                        warn "Usuario '$USERNAME' nao criado nem adicionado ao grupo ${GROUP_ADMIN}"
                    fi
                fi
                ;;
            2)
                echo "Resetando e adicionando grupo ao sistema..."
                echo "" > "${GROUPS_FILE}"
                if ! getent group user.vpn >/dev/null; then
                    groupadd user.vpn && info "Grupo user.vpn criado" || error "Erro ao criar grupo user.vpn"
                else
                    info "Grupo user.vpn ja existe"
                fi
                echo "user.vpn" >> "${GROUPS_FILE}"
                info "Grupo user.vpn preparado"
                ;;
            3)
                echo "Resetando e adicionando grupos ao sistema..."
                echo "" > "${GROUPS_FILE}"
                read -r -p "Digite o nome dos grupos separados por espaco (ex: financeiro.vpn comercial.vpn): " grupos
                if [ -z "$grupos" ]; then
                    warn "Nenhum grupo digitado. Voltando ao menu."
                    continue
                fi
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
                systemctl start ${SERVICE_NAME}
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