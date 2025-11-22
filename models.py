from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)

class TipoEmpleado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    tipo_empleado_id = db.Column(db.Integer, db.ForeignKey('tipo_empleado.id'), nullable=False)

    role = db.relationship('Role', backref=db.backref('users', lazy=True))
    tipoEmpleado = db.relationship('TipoEmpleado', backref=db.backref('users', lazy=True))

# Modelo de accesorios/autopartes en stock
class Accesorio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(50), unique=True, nullable=False)
    lote = db.Column(db.String(50), nullable=False)
    marca = db.Column(db.String(100), nullable=False)
    nombre = db.Column(db.String(150), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    sucursal = db.Column(db.String(50), nullable=False)
