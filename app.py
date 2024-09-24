from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key" # Secret Key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' # Caminho do banco de dados

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
# Ativar a conexão (sessão)

# Usar a rota de login para login
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        # Login
        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autenticação realizada com sucesso"})
    
    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route('/logout', methods=['GET'])
@login_required # Decorator utilizado apenas para usuarios autenticados
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"})

@app.route('/user', methods=["POST"])
# @login_required -> Caso eu queira apenas deixar que usuarios logados cadastrem usuarios
def create_user():
    data = request.json # Receber a informação de criação de usuário
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User(username=username, password=password)
        db.session.add(user) # acrescentando o usuario
        db.session.commit() # usando a sessão para adicionar o usuario
        return jsonify({"message": "Usuário cadastrado com sucesso"})

    return jsonify({"message": "Dados inválidos"}), 401 # Dados não corretos

@app.route('/user/<int:id_user>', methods=['GET']) # Quero que na rota user, o ID que eu recupere seja inteiro
@login_required
def read_user(id_user):
    user = User.query.get(id_user) # Recuperando o ID do usuário

    if user:
        return {"username": user.username}
    
    return jsonify({"message": "Usuário não encontrado"}), 404

'''
Sempre que eu for mexer no banco de dados, seja pra adicionar, atualizar. Preciso fazer um commit na session

Não atualizar o username, pois as rotas utilizam dele

'''

@app.route('/user/<int:id_user>', methods=['PUT']) # Quero que na rota user, o ID que eu ATUALIZE seja inteiro
@login_required
def update_user(id_user):
    data = request.json # Recuperar o que o usuário mandou
    user = User.query.get(id_user) # Recuperando o ID do usuário

    if user and data.get("password"): # Tem que ter enviado a senha e o usuário
        user.password = data.get("password") # Recuperando o password
        db.session.commit() # usando a sessão para atualizar o usuario

        return jsonify({"message": f"Usuário {id_user} atualizado com sucesso"})
    
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=['DELETE']) # Quero que na rota user, o ID que eu recupere seja inteiro
@login_required
def delete_user(id_user):
    user = User.query.get(id_user) # Recuperando o ID do usuário

    if id_user == current_user.id:
        return jsonify({"message": "Deleção não permitida"}), 403

    if user and id_user != current_user.id: # O usuário autenticado tem que ser diferente do usuário que está para ser deletado
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {id_user} deletado com sucesso!"})
    
    return jsonify({"message": "Usuário não encontrado"}), 404

if __name__=='__main__':
    app.run(debug=True)
