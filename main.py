from flask import Flask, request, redirect, url_for, session, render_template, jsonify, flash # type: ignore
import spwd # type: ignore
import crypt # type: ignore
import grp # type: ignore
import os
import subprocess

app = Flask(__name__)
app.secret_key = os.urandom(24)

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


######################### CRUD de usuários ###############################
def create_user_and_add_to_group(username: str, password: str, groupname: str) -> bool:
    try:
        # Cria o usuário e o adiciona ao grupo
        subprocess.run(
            ["useradd", "-m", "-G", groupname, username],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print(f"Usuário '{username}' criado e adicionado ao grupo '{groupname}' com sucesso.")
        
        # Define a senha do usuário
        subprocess.run(
            ["chpasswd"],
            input=f"{username}:{password}".encode(),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print(f"Senha para o usuário '{username}' definida com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erro ao criar o usuário ou configurar senha: {e.stderr.decode()}")
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

def change_user_group(username: str, groupname: str) -> bool:
    if not check_user_in_groups(username):
        return False

    try:
        subprocess.run(["usermod", "-G", groupname, username], check=True)
        print(f"Grupo do usuário '{username}' alterado com sucesso para '{groupname}'.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erro ao alterar o grupo do usuário '{username}': {e.stderr.decode()}")
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


######################### ROUTES #########################################

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
                 # Verifica se o usuário pertence ao grupo "vpn.admin.valorup"
                try:
                    group_info = grp.getgrnam('vpn.admin.valorup')
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

    return render_template('login_screen.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/vpn_users')
def vpn_users():
    # if 'username' in session:
    #     username = session['username']  # Obtém o nome do usuário da sessão
    #     return render_template('users.html', username=username)
    # else:
    #     return redirect(url_for('login'))
    username = "ralves"
    return render_template('users.html', username=username)

######################### API ############################################

@app.route('/get_groups', methods=['GET'])
def get_groups():
    return jsonify(list_groups())

@app.route('/get_users', methods=['GET'])
def get_users():
    # if 'username' in session:
    grupos = list_groups()  # Lê os grupos do arquivo
    resultado = {}

    for grupo in grupos:
        try:
            # Obtém informações sobre o grupo
            info_grupo = grp.getgrnam(grupo)
            # Para cada membro do grupo, cria um dicionário com informações do usuário
            membros = []
            for usuario in info_grupo.gr_mem:
                try:
                    # Verifica se o usuário está bloqueado verificando se a senha começa com '!'
                    user_info = spwd.getspnam(usuario)
                    status = not user_info.sp_pwdp.startswith('!')
                    membros.append({
                        'username': usuario,
                        'active': status
                    })
                except KeyError:
                    # Se não conseguir obter informações do usuário, assume que está inativo
                    membros.append({
                        'username': usuario,
                        'active': False
                    })
            resultado[grupo] = membros
        except KeyError:
            # Se o grupo não existir, adiciona uma lista vazia
            resultado[grupo] = []
    return jsonify(resultado)  # Retorna o resultado como JSON
    # else:
    #     return redirect(url_for('login'))

@app.route('/add_user', methods=['POST'])
def add_user():
    # if 'username' in session:
    user = request.form['user']
    password = request.form['pass']
    group = request.form['group']

    if create_user_and_add_to_group(user, password, group):
        return jsonify({'success': True, 'message': 'Usuário criado com sucesso'})
    else:
        return jsonify({'success': False, 'message': 'Erro, veja o log no terminal'})
    # else:
    #     return redirect(url_for('login'))

@app.route('/remove_user', methods=['POST'])
def remove_user():
    # if 'username' in session:
    user = request.form['user']
    if delete_user(user):
        return jsonify({'success': True, 'message': 'Usuário deletado com sucesso'})
    else:
        return jsonify({'success': False, 'message': 'Erro, veja o log no terminal'})
    # else:
    #     return redirect(url_for('login'))

@app.route('/change_password', methods=['POST'])
def change_password():
    data = request.get_json()  # Alterado para pegar dados JSON
    user = data['change_password_user']
    password = data['change_password_pass']
    if change_user_password(user, password):
        return jsonify({'success': True, 'message': 'Senha alterada com sucesso'})
    else:
        return jsonify({'success': False, 'message': 'Erro, veja o log no terminal'})
    
@app.route('/change_group', methods=['POST'])
def change_group():
    data = request.get_json()  # Alterado para pegar dados JSON
    user = data['change_group_user']
    group = data['change_group_group']
    if change_user_group(user, group):
        return jsonify({'success': True, 'message': 'Grupo alterado com sucesso'})
    else:
        return jsonify({'success': False, 'message': 'Erro, veja o log no terminal'})

@app.route('/lock_user', methods=['POST'])
def lock_user():
    data = request.get_json()  # Alterado para pegar dados JSON
    user = data['user_to_lock']
    if disable_user(user):
        return jsonify({'success': True, 'message': 'Usuário bloqueado com sucesso'})
    else:
        return jsonify({'success': False, 'message': 'Erro, veja o log no terminal'})

@app.route('/unlock_user', methods=['POST'])
def unlock_user():
    data = request.get_json()  # Alterado para pegar dados JSON
    user = data['user_to_unlock']
    if enable_user(user):
        return jsonify({'success': True, 'message': 'Usuário ativado com sucesso'})
    else:
        return jsonify({'success': False, 'message': 'Erro, veja o log no terminal'})

##########################################################################









if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context=('./ssl_certs/cert.pem', './ssl_certs/key.pem'), debug=True)