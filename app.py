from flask import Flask, render_template, request, redirect, url_for, flash
from models import db, User, Role, TipoEmpleado
from werkzeug.security import check_password_hash
from flask import session
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'clave-secreta'  # Para mensajes flash y sesión

db.init_app(app)

# Crear tablas al iniciar
with app.app_context():
    db.create_all()

    # Crear roles y tipos si no existen
    if not Role.query.filter_by(nombre='Administrador').first():
        db.session.add(Role(nombre='Administrador'))
    if not Role.query.filter_by(nombre='Empleado').first():
        db.session.add(Role(nombre='Empleado'))
    for tipo in ['Cajero', 'Vendedor', 'Almacenero']:
        if not TipoEmpleado.query.filter_by(nombre=tipo).first():
            db.session.add(TipoEmpleado(nombre=tipo))
    db.session.commit()

    # Crear usuario admin por defecto
    admin_email = 'coco_sori@hotmail.com'
    admin_password = generate_password_hash('cocosor')
    admin_role = Role.query.filter_by(nombre='Administrador').first()
    if not User.query.filter_by(email=admin_email).first():
        db.session.add(User(
            name='Administrador',
            email=admin_email,
            password=admin_password,
            role_id=admin_role.id,
            tipo_empleado_id=1  # Puede ser cualquier tipo, no relevante para admin
        ))
        db.session.commit()

# ------------------- Rutas -------------------

# Decorador para restringir acceso solo al admin
def solo_admin(f):
    from functools import wraps
    @wraps(f)
    def decorador(*args, **kwargs):
        usuario = session.get('usuario')
        if not usuario or usuario.get('role') != 'Administrador':
            flash('Acceso restringido solo para el administrador.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorador

# Ruta de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        usuario = User.query.filter_by(email=email).first()
        if usuario and check_password_hash(usuario.password, password):
            role = usuario.role.nombre
            session['usuario'] = {'id': usuario.id, 'email': usuario.email, 'role': role}
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales incorrectas', 'danger')
    return render_template('login.html')

# Ruta de logout
@app.route('/logout')
def logout():
    session.pop('usuario', None)
    flash('Sesión cerrada', 'info')
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    usuario = session.get('usuario')
    return render_template('dashboard.html', usuario=usuario)


@app.route('/usuarios')
@solo_admin
def listar_usuarios():
    usuarios = User.query.all()
    return render_template('usuarios.html', usuarios=usuarios)


@app.route('/usuarios/crear', methods=['GET', 'POST'])
@solo_admin
def crear_usuario():
    roles = Role.query.all()
    tipos = TipoEmpleado.query.all()
    sucursales = [{'id': 1, 'nombre': 'Sucursal Norte'}, {'id': 2, 'nombre': 'Sucursal Sur'}, {'id': 3, 'nombre': 'Sucursal Centro'}]

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        tipo_usuario = request.form['tipo_usuario']
        categoria = request.form.get('categoria')
        sucursal = request.form['sucursal']

        if tipo_usuario == 'Administrador':
            role = Role.query.filter_by(nombre='Administrador').first()
            tipo_empleado = TipoEmpleado.query.first()  # No relevante para admin
        else:
            role = Role.query.filter_by(nombre='Empleado').first()
            tipo_empleado = TipoEmpleado.query.filter_by(nombre=categoria).first()

        nuevo_usuario = User(
            name=name,
            email=email,
            password=password,
            role_id=role.id,
            tipo_empleado_id=tipo_empleado.id
        )
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash('Usuario creado correctamente', 'success')
        return redirect(url_for('listar_usuarios'))

    return render_template('crear_usuario.html', roles=roles, tipos=tipos, sucursales=sucursales)


@app.route('/usuarios/<int:id>/editar', methods=['GET', 'POST'])
@solo_admin
def editar_usuario(id):
    usuario = User.query.get_or_404(id)
    roles = Role.query.all()
    tipos = TipoEmpleado.query.all()

    if request.method == 'POST':
        usuario.name = request.form['name']
        usuario.email = request.form['email']
        usuario.role_id = request.form['role_id']
        usuario.tipo_empleado_id = request.form['tipo_empleado_id']
        db.session.commit()
        flash('Usuario actualizado correctamente', 'success')
        return redirect(url_for('listar_usuarios'))

    return render_template('editar_usuario.html', usuario=usuario, roles=roles, tipos=tipos)


if __name__ == '__main__':
    app.run(debug=True)
