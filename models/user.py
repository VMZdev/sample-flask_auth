from database import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    # id (int), username (text), password (text)
    id = db.Column(db.Integer, primary_key=True) # Chave primaria dessa tabela (única, ROOT)
    username = db.Column(db.String(80), nullable=False, unique=True) # nullable = True -> Eu aceito um registro sem valor | unique = True -> O usuario não pode repetir
    password = db.Column(db.String(80), nullable=False)

