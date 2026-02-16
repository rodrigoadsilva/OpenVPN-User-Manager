#!/bin/bash
set -euo pipefail

# Script para criar 15 usuários de teste com nomes realistas (first.last)
# Garante pelo menos 2 usuários com o mesmo primeiro nome e 3 com o mesmo sobrenome
# Senha fixa: Mudar@123
# Execute como root: sudo ./create_test_users.sh

GROUP="user.vpn"
PASSWORD='Mudar@123'
NUM_USERS=15
OUTPUT_FILE="created_test_users.txt"

# Verifica se está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
  echo "Por favor execute como root (sudo)"
  exit 1
fi

# Garante que o grupo exista
if ! getent group "$GROUP" >/dev/null 2>&1; then
  echo "Grupo $GROUP nao existe. Criando..."
  if groupadd "$GROUP"; then
    echo "Grupo $GROUP criado"
  else
    echo "Falha ao criar o grupo $GROUP" >&2
    exit 1
  fi
else
  echo "Grupo $GROUP ja existe"
fi

# Listas de nomes e sobrenomes
FIRST_NAMES=("lucas" "carlos" "joao" "maria" "ana" "rodrigo" "paulo" "bruno" "felipe" "rafael" "marcos" "pedro" "mariana" "camila" "juliana")
LAST_NAMES=("pereira" "silva" "santos" "oliveira" "souza" "lima" "rocha" "alves" "costa" "carvalho" "barros" "mendes" "gomes" "ribeiro" "ferreira")

# Função para escolher um elemento aleatório de um array
random_choice() {
  local arr=("${!1}")
  echo "${arr[RANDOM % ${#arr[@]}]}"
}

# Prepara as exigências: pelo menos 2 com mesmo primeiro nome e 3 com o mesmo sobrenome
duplicate_first=$(random_choice FIRST_NAMES[@])
common_surname=$(random_choice LAST_NAMES[@])

# Garantir que common_surname possa ser reutilizado mesmo se for igual ao gerado abaixo

# Array temporária de nomes completos (first last)
declare -a FULL_NAMES

# Adiciona 2 usuários com o mesmo primeiro nome (sobrenomes aleatórios)
for i in 1 2; do
  last=$(random_choice LAST_NAMES[@])
  # evita repetir exatamente o mesmo full name para as duas entradas
  if [ $i -eq 2 ] && [ "${FULL_NAMES[0]}" = "${duplicate_first}.${last}" ]; then
    last=$(random_choice LAST_NAMES[@])
  fi
  FULL_NAMES+=("${duplicate_first}.${last}")
done

# Adiciona 3 usuários com o mesmo sobrenome (primeiros aleatórios)
for i in 1 2 3; do
  first=$(random_choice FIRST_NAMES[@])
  # evita que seja igual a uma já existente; em caso, escolhe outro
  fullname="${first}.${common_surname}"
  tries=0
  while printf '%s\n' "${FULL_NAMES[@]}" | grep -qx "$fullname"; do
    first=$(random_choice FIRST_NAMES[@])
    fullname="${first}.${common_surname}"
    tries=$((tries+1))
    if [ $tries -ge 10 ]; then
      break
    fi
  done
  FULL_NAMES+=("$fullname")
done

# Preenche o restante até NUM_USERS com combinações aleatórias
while [ ${#FULL_NAMES[@]} -lt $NUM_USERS ]; do
  first=$(random_choice FIRST_NAMES[@])
  last=$(random_choice LAST_NAMES[@])
  FULL_NAMES+=("${first}.${last}")
done

# Normaliza nomes (lowercase and remove accents if any) and garante unicidade de username
> "$OUTPUT_FILE"

echo "Gerando ${NUM_USERS} usuarios de teste (senha: $PASSWORD) e adicionando ao grupo $GROUP..."

declare -A SEEN_USERNAMES
count=0
for fullname in "${FULL_NAMES[@]}"; do
  # transforma em username (já no formato first.last)
  username=$(echo "$fullname" | tr '[:upper:]' '[:lower:]' | tr -s ' ' '_' | tr -cd 'a-z0-9._')

  # Se já existir no sistema ou na lista, acrescenta sufixo numérico até ficar único
  base_username="$username"
  suffix=1
  while id "$username" >/dev/null 2>&1 || [ "${SEEN_USERNAMES[$username]+_}" ]; do
    username="${base_username}.${suffix}"
    suffix=$((suffix+1))
  done

  # Tenta criar o usuário
  if useradd -m -s /bin/bash -G "$GROUP" "$username"; then
    if printf '%s:%s\n' "$username" "$PASSWORD" | chpasswd; then
      echo "$username" | tee -a "$OUTPUT_FILE"
      echo "Criado: $username"
      SEEN_USERNAMES[$username]=1
      count=$((count+1))
    else
      echo "Falha ao definir senha para $username" >&2
      userdel -r "$username" >/dev/null 2>&1 || true
    fi
  else
    echo "Falha ao criar usuario $username" >&2
  fi

  # Se chegamos ao número desejado, para
  if [ $count -ge $NUM_USERS ]; then
    break
  fi
done

echo "Concluido. $count usuarios criados. Lista em $OUTPUT_FILE"
