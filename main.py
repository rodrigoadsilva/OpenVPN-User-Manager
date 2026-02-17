from flask import Flask, request, redirect, url_for, session, render_template, jsonify, flash
import spwd
import crypt
import grp
import os
import subprocess
import datetime
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configura logging para debug em arquivo separado
logging.basicConfig(
    filename='debug.log',
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
)

grupo_admin = 'openvpn.admin'

######################### FUNÇÕES BASICAS #########################################

# Função para ler o arquivo de empresas (grupos)
def list_groups():
    try:
        with open('groups.txt', 'r') as f:
            # Lê todas as linhas, remove os espaços em branco ao redor e ignora linhas vazias
            grupos = [linha.strip() for linha in f.readlines() if linha.strip()]
        return grupos
    except FileNotFoundError:
        return []  # Retorna lista vazia se o arquivo não for encontrado

# Função para registrar operações no arquivo de log
def registrar_log(operacao: str, usuario_executante: str, detalhes: str) -> None:
   """
   Registra operações no arquivo de log
   """
   timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
   log_entry = f"[{timestamp}] {usuario_executante} - {operacao}: {detalhes}\n"
   
   with open('operacoes.log', 'a') as f:
       f.write(log_entry)

######################### CRUD de usuários ###############################

def create_user_and_add_to_group(username: str, password: str, groupname: str) -> bool:
    try:
        # Cria o usuário e o adiciona ao grupo
        logging.debug(f"Criando usuário '{username}' no grupo '{groupname}'")
        subprocess.run(
            ["useradd", "-m", "-G", groupname, username],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        logging.info(f"Usuário '{username}' criado e adicionado ao grupo '{groupname}'.")

        # Define a senha do usuário
        logging.debug(f"Definindo senha para usuário '{username}'")
        subprocess.run(
            ["chpasswd"],
            input=f"{username}:{password}".encode(),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        logging.info(f"Senha para o usuário '{username}' definida com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        stderr = ''
        try:
            stderr = e.stderr.decode()
        except Exception:
            stderr = str(e)
        logging.error(f"Erro ao criar o usuário ou configurar senha para '{username}': {stderr}")
        logging.debug("CalledProcessError details:", exc_info=True)
        return False

def check_user_in_groups(username: str) -> bool:
    grupos = list_groups()
    usuario_autorizado = False
    
    for grupo in grupos:
        try:
            group_info = grp.getgrnam(grupo)
            if username in group_info.gr_mem:
                usuario_autorizado = True
                break
        except KeyError:
            continue
            
    if not usuario_autorizado:
        print(f"Usuário '{username}' não pertence a nenhum grupo autorizado")
        return False
        
    return True

def change_user_password(username: str, password: str) -> bool:
    if not check_user_in_groups(username):
        return False
        
    try:
        subprocess.run(["chpasswd"], input=f"{username}:{password}".encode(), check=True)
        print(f"Senha para o usuário '{username}' definida com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erro ao definir a senha para o usuário '{username}': {e.stderr.decode()}")
        return False

def change_user_group(username: str, groups: list) -> bool:
    if not check_user_in_groups(username):
        return False

    try:
        # Junta os grupos com vírgula para o comando usermod
        groups_str = ','.join(groups)
        subprocess.run(["usermod", "-G", groups_str, username], check=True)
        print(f"Grupos do usuário '{username}' alterados com sucesso para '{groups_str}'.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erro ao alterar os grupos do usuário '{username}': {e.stderr.decode()}")
        return False

def delete_user(username: str) -> bool:
    if not check_user_in_groups(username):
        return False

    try:
        # Comando para remover o usuário e o diretório home
        subprocess.run(
            ["userdel", "-r", username],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print(f"Usuário '{username}' removido com sucesso, incluindo o diretório home.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erro ao remover o usuário '{username}': {e.stderr.decode()}")
        return False

def enable_user(username: str) -> bool:
    if not check_user_in_groups(username):
        return False

    try:
        subprocess.run(["sudo", "usermod", "--unlock", username], check=True)
        print(f"Usuário '{username}' ativado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erro ao ativar o usuário '{username}': {e.stderr.decode()}")
        return False

def disable_user(username: str) -> bool:
    if not check_user_in_groups(username):
        return False

    try:
        subprocess.run(["sudo", "usermod", "--lock", username], check=True)
        print(f"Usuário '{username}' desabilitado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erro ao desabilitar o usuário '{username}': {e.stderr.decode()}")
        return False
    
##########################################################################

############### CONFIGURAÇÃO DE GERAÇÃO DE SENHA #########################
def get_genpass_config():
    config = {
        'length': 12,
        'lowercase': True,
        'uppercase': True,
        'numbers': True,
    }

    try:
        with open('genpass.conf', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue  # Ignora linhas vazias e comentários
                key, value = line.split('=')
                key = key.strip().lower()
                value = value.strip().lower()
                
                if key == 'length':
                    config['length'] = int(value)
                elif key in ['lowercase', 'uppercase', 'numbers']:
                    config[key] = value == 'true'

        return config
    except FileNotFoundError:
        return config  # Retorna configuração padrão se o arquivo não for encontrado
    
def change_genpass_config(length: int, lowercase: bool, uppercase: bool, numbers: bool) -> bool:
    try:
        with open('genpass.conf', 'w') as f:
            f.write(f"LENGTH={length}\n")
            f.write(f"LOWERCASE={'true' if lowercase else 'false'}\n")
            f.write(f"UPPERCASE={'true' if uppercase else 'false'}\n")
            f.write(f"NUMBERS={'true' if numbers else 'false'}\n")
        return True
    except Exception as e:
        print(f"Erro ao salvar a configuração de geração de senha: {e}")
        return False

##########################################################################

######################### ROUTES #########################################

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            # Obtém o hash da senha do usuário
            user_info = spwd.getspnam(username)
            hash_pw = user_info.sp_pwdp

            # Verifica a senha fornecida
            if crypt.crypt(password, hash_pw) == hash_pw:
                # Verifica se o usuário pertence ao grupo "openvpn.admin"
                try:
                    group_info = grp.getgrnam(grupo_admin)
                    if username in group_info.gr_mem:
                        session['username'] = username
                        return redirect(url_for('vpn_users'))
                    else:
                        flash('Falha no login. Usuário não pertence ao grupo requisitado.')
                except KeyError:
                    flash('Falha no login. Grupo não existe.')
            else:
                flash('Falha no login. Credencial inválida.')
        except KeyError:
            flash('Falha no login. Usuário não existe.')

    return render_template('login_screen_new.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/vpn_users')
def vpn_users():
    if 'username' in session:
        username = session['username']  # Obtém o nome do usuário da sessão
        return render_template('users_new.html', username=username)
    else:
        return redirect(url_for('login'))

######################### API ############################################

@app.route('/get_groups', methods=['GET'])
def get_groups():
    if 'username' in session:
        return jsonify(list_groups())
    return redirect(url_for('login'))

@app.route('/get_admins', methods=['GET'])
def get_admins():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    try:
        group_info = grp.getgrnam(grupo_admin)
        admins = group_info.gr_mem
        return jsonify(admins)
    except KeyError:
        return jsonify([])  # Retorna lista vazia se o grupo não existir

@app.route('/get_users', methods=['GET'])
def get_users():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    grupos = list_groups()
    usuarios = {}  # Dicionário para armazenar informações dos usuários

    for grupo in grupos:
        try:
            info_grupo = grp.getgrnam(grupo)
            for usuario in info_grupo.gr_mem:
                # Se já existe no dict, só acrescenta grupo
                if usuario in usuarios:
                    usuarios[usuario]['groups'].append(grupo)
                    continue

                # Determinar se o usuário está ativo
                try:
                    user_info = spwd.getspnam(usuario)
                    status = not user_info.sp_pwdp.startswith('!')
                except KeyError:
                    # Shadow não existe. Verificar se existe no passwd.
                    try:
                        pwd.getpwnam(usuario)  # type: ignore
                        status = True  # Existe como conta válida
                    except KeyError:
                        status = False  # Não existe no sistema

                usuarios[usuario] = {
                    'username': usuario,
                    'active': status,
                    'groups': [grupo]
                }

        except KeyError:
            pass # Grupo não existe, ignora

    return jsonify(list(usuarios.values()))

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'username' in session:
        try:
            user = request.form['user']
            password = request.form['pass']
            groups = request.form['groups'].split(',')

            logging.debug(f"/add_user chamado por '{session['username']}' -> user='{user}', groups={groups}")

            # Cria o usuário com o primeiro grupo
            if create_user_and_add_to_group(user, password, groups[0]):
                # Se houver mais grupos, adiciona o usuário a eles
                if len(groups) > 1:
                    if change_user_group(user, groups):
                        registrar_log(
                            operacao="CRIAR_USUARIO",
                            usuario_executante=session['username'],
                            detalhes=f"Criou usuário '{user}' nos grupos '{', '.join(groups)}'"
                        )
                        logging.info(f"Usuário '{user}' criado nos grupos {groups} com sucesso")
                        return jsonify({'success': True, 'message': 'Usuário criado com sucesso'})
                    else:
                        # Se falhar ao adicionar aos grupos adicionais, remove o usuário
                        logging.error(f"Falha ao adicionar '{user}' aos grupos adicionais: {groups}")
                        delete_user(user)
                        registrar_log(
                            operacao="ERRO_CRIAR_USUARIO",
                            usuario_executante=session['username'],
                            detalhes=f"Falha ao adicionar '{user}' aos grupos adicionais {', '.join(groups)}"
                        )
                        return jsonify({'success': False, 'message': 'Erro ao adicionar grupos adicionais'})
                else:
                    registrar_log(
                        operacao="CRIAR_USUARIO",
                        usuario_executante=session['username'],
                        detalhes=f"Criou usuário '{user}' no grupo '{groups[0]}'"
                    )
                    logging.info(f"Usuário '{user}' criado no grupo {groups[0]} com sucesso")
                    return jsonify({'success': True, 'message': 'Usuário criado com sucesso'})
            else:
                logging.error(f"create_user_and_add_to_group retornou False para usuário '{user}'")
                registrar_log(
                    operacao="ERRO_CRIAR_USUARIO",
                    usuario_executante=session['username'],
                    detalhes=f"Erro ao criar usuário '{user}' no grupo '{groups[0]}'"
                )
                return jsonify({'success': False, 'message': 'Erro ao criar usuário'})
        except Exception as exc:
            logging.exception(f"Exceção inesperada no endpoint /add_user: {exc}")
            # Registrar falha geral
            registrar_log(
                operacao="ERRO_CRIAR_USUARIO",
                usuario_executante=session.get('username', 'desconhecido'),
                detalhes=f"Exceção ao criar usuário: {str(exc)}"
            )
            return jsonify({'success': False, 'message': 'Erro interno ao criar usuário'})
    return redirect(url_for('login'))

@app.route('/remove_user', methods=['POST'])
def remove_user():
    if 'username' in session:
       data = request.get_json()
       user = data['user_to_delete']
       
       if delete_user(user):
           registrar_log(
               operacao="REMOVER_USUARIO",
               usuario_executante=session['username'],
               detalhes=f"Removeu usuário '{user}'"
           )
           return jsonify({'success': True, 'message': 'Usuário deletado com sucesso'})
       else:
           return jsonify({'success': False, 'message': 'Erro, veja o log no terminal'})
    return redirect(url_for('login'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' in session:
       data = request.get_json()
       user = data['change_password_user']
       password = data['change_password_pass']
       
       if change_user_password(user, password):
           registrar_log(
               operacao="ALTERAR_SENHA",
               usuario_executante=session['username'],
               detalhes=f"Alterou senha do usuário '{user}'"
           )
           return jsonify({'success': True, 'message': 'Senha alterada com sucesso'})
       else:
           return jsonify({'success': False, 'message': 'Erro, veja o log no terminal'})
    return redirect(url_for('login'))
    
@app.route('/change_group', methods=['POST'])
def change_group():
    if 'username' in session:
        data = request.get_json()
        user = data['change_group_user']
        groups = data['change_group_groups']
        
        if change_user_group(user, groups):
            registrar_log(
                operacao="ALTERAR_GRUPOS",
                usuario_executante=session['username'],
                detalhes=f"Alterou grupos do usuário '{user}' para '{', '.join(groups)}'"
            )
            return jsonify({'success': True, 'message': 'Grupos alterados com sucesso'})
        else:
            return jsonify({'success': False, 'message': 'Erro, veja o log no terminal'})
    return redirect(url_for('login'))

@app.route('/lock_user', methods=['POST'])
def lock_user():
    if 'username' in session:
        data = request.get_json()  # Alterado para pegar dados JSON
        user = data['user_to_lock']
        if disable_user(user):
            registrar_log(
                operacao="BLOQUEAR_USUARIO",
                usuario_executante=session['username'],
                detalhes=f"Bloquear usuário '{user}'"
            )
            return jsonify({'success': True, 'message': 'Usuário bloqueado com sucesso'})
        else:
            return jsonify({'success': False, 'message': 'Erro, veja o log no terminal'})
    return redirect(url_for('login'))

@app.route('/unlock_user', methods=['POST'])
def unlock_user():
    if 'username' in session:
        data = request.get_json()  # Alterado para pegar dados JSON
        user = data['user_to_unlock']
        if enable_user(user):
            registrar_log(
                operacao="DESBLOQUEAR_USUARIO",
                usuario_executante=session['username'],
                detalhes=f"Desbloquear usuário '{user}'"
            )
            return jsonify({'success': True, 'message': 'Usuário ativado com sucesso'})
        else:
            return jsonify({'success': False, 'message': 'Erro, veja o log no terminal'})
    return redirect(url_for('login'))

@app.route('/get_genpass_config', methods=['GET'])
def load_genpass_config():
    config = get_genpass_config()
    return jsonify(config)

@app.route('/change_genpass_config', methods=['POST'])
def change_genpass_config_endpoint():
    data = request.get_json()
    length = data.get('length')
    lowercase = data.get('lowercase')
    uppercase = data.get('uppercase')
    numbers = data.get('numbers')
    
    if change_genpass_config(length, lowercase, uppercase, numbers):
        return jsonify({'success': True, 'message': 'Configuração de geração de senha alterada com sucesso'})
    else:
        return jsonify({'success': False, 'message': 'Erro ao alterar configuração de geração de senha'})

##########################################################################

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3223, ssl_context=('./ssl_certs/cert.pem', './ssl_certs/key.pem'), debug=True)