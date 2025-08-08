from flask import Flask, app, render_template, request
from flask_login import login_required, current_user, login_user, logout_user, LoginManager
from online_restaurant_db import Session, Menu, Users, Orders, Reservation, Position, AdminMessage
from sqlalchemy import create_engine, ForeignKey, String, Boolean, DateTime
from flask import flash, redirect, url_for, session
import secrets
from datetime import datetime
import os
import uuid
from sqlalchemy.orm import sessionmaker, relationship, Mapped, mapped_column, joinedload
import bcrypt
import openai
from flask_babel import Babel, gettext as _

app = Flask(__name__)
babel = Babel(app)
app.secret_key = secrets.token_hex(32)  
@app.before_request
def set_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

openai.api_key = os.getenv("OPENAI_API_KEY")

LANGUAGES = {'en': 'English', 'uk': 'Українська', 'ja': '日本語'}

def get_locale():
    lang = request.args.get('lang')
    if lang in LANGUAGES:
        return lang
    return request.accept_languages.best_match(LANGUAGES.keys())

babel.locale_selector_func = get_locale

FILES_PATH = 'static/menu'
MARGANETS_COORDS = (47.6383, 34.6421)
KYIV_RADIUS_KM = 100

TABLE_NUM = {
    "1-2": 5,
    "3-4": 4,
    "4+": 2
}

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
app.config['MAX_FORM_MEMORY_SIZE'] = 1024 * 1024  
app.config['MAX_FORM_PARTS'] = 500

app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

app.config['SECRET_KEY'] = '#cv)3v7w$*s3fk;5c!@y0?:?№3"9)#'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    with Session() as session:
        user = session.query(Users).filter_by(id = user_id).first()
        if user:
            return user

@app.after_request
def apply_csp(response):
    nonce = secrets.token_urlsafe(16)  
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"img-src 'self' data:; "
        f"form-action 'self';"
    )

    response.headers['Content-Security-Policy'] = csp
    response.set_cookie('nonce', nonce)
    return response

@app.route('/')
@app.route('/home')
def home():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    return render_template('home.html')

@app.route("/register", methods = ['GET','POST'])
def register():
    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403
        nickname = request.form['nickname']
        email = request.form['email']
        password = request.form['password']

        with Session() as cursor:
            if cursor.query(Users).filter_by(email=email).first() or cursor.query(Users).filter_by(nickname = nickname).first():
                flash('User with this email or nickname already exists!', 'danger')
                return render_template('register.html',csrf_token=session["csrf_token"])

            new_user = Users(nickname=nickname, email=email)
            new_user.set_password(password)
            cursor.add(new_user)
            cursor.commit()
            cursor.refresh(new_user)
            login_user(new_user)
            return redirect(url_for('welcome'))
        
    return render_template('register.html',csrf_token=session["csrf_token"])

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("csrf_token") != session.get("csrf_token"):
            return "Request blocked!", 403

        email = request.form["email"]
        password = request.form["password"]

        with Session() as cursor:
            user = cursor.query(Users).filter_by(email=email).first()
            if user and user.check_password(password):
                login_user(user)

                return redirect(url_for("welcome"))

            flash("Invalid email or password!")
            return redirect(url_for("login"))

    return render_template("login.html", csrf_token=session.get("csrf_token"))

@app.route("/welcome")
@login_required
def welcome():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    if current_user.nickname == 'Admin':
        return redirect(url_for('admin_panel'))
    return render_template('welcome.html', user=current_user)

@app.route("/add_position", methods=['GET', 'POST'])
@login_required
def add_position():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    if request.method == "POST":
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403

        name = request.form['name']
        file = request.files.get('img')
        ingredients = request.form['ingredients']
        description = request.form['description']
        price = request.form['price']
        weight = request.form['weight']

        if not file or not file.filename:
            return 'File not selected or upload failed'

        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        output_path = os.path.join('static/menu', unique_filename)

        with open(output_path, 'wb') as f:
            f.write(file.read())

        with Session() as cursor:
            new_position = Menu(name=name, ingredients=ingredients, description=description,
                                price=price, weight=weight, file_name=unique_filename)
            cursor.add(new_position)
            cursor.commit()

        flash('Position added successfully!')

    return render_template('add_position.html', csrf_token=session["csrf_token"])

@app.route('/menu')
def menu():
    with Session() as session:
        all_positions = session.query(Menu).filter_by(active = True).all()
    return render_template("menu.html", all_positions=all_positions)

@app.route('/position/<name>', methods = ['GET','POST'])
def position(name):
    if request.method == 'POST':

        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403

        position_name = request.form.get('name')
        position_num = request.form.get('num')
        if 'basket' not in session:
            basket = {}
            basket[position_name] = position_num
            session['basket'] = basket
        else:
            basket = session.get('basket')
            basket[position_name] = position_num
            session['basket'] = basket
        flash('This position has been added to the basket!')
    with Session() as cursor:
        us_position = cursor.query(Menu).filter_by(active = True, name = name).first()
    return render_template('position.html', csrf_token=session["csrf_token"] ,position = us_position)


@app.route('/create_order', methods=['GET','POST'])
@login_required
def create_order():
    basket = session.get('basket')
    if request.method == 'POST':

        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403

        if not current_user:
            flash("For creating an order, you need to log in!")
        else:
            if not basket:
                flash("Your basket is empty")
            else:
                with Session() as cursor:
                    new_order = Orders(order_list = basket,order_time = datetime.now(), user_id=current_user.id)
                    cursor.add(new_order)
                    cursor.commit()
                    session.pop('basket')
                    cursor.refresh(new_order)
                    return redirect(f"/my_order/{new_order.id}")

    return render_template('create_order.html', csrf_token=session["csrf_token"], basket=basket)

@app.route('/basket')
@login_required
def basket():
    session_basket = session.get('basket', {})
    if not session_basket:
        flash("Your basket is empty")
        return render_template('basket.html', basket=[], total_price=0)

    display_basket = []
    total_price = 0

    with Session() as cursor:
        for item_name, quantity in session_basket.items():
            menu_item = cursor.query(Menu).filter_by(name=item_name).first()
            if menu_item:
                item_data = {
                    "name": menu_item.name,
                    "price": menu_item.price,
                    "image": menu_item.file_name,
                    "quantity": int(quantity)
                }
                display_basket.append(item_data)
                total_price += menu_item.price * int(quantity)

    return render_template(
        'basket.html',
        basket=display_basket,
        total_price=total_price
    )

@app.route('/remove_from_basket', methods=['POST'])
@login_required
def remove_from_basket():
    item_to_remove = request.form.get('item_name')
    if item_to_remove and 'basket' in session:
        session['basket'].pop(item_to_remove, None)
        session.modified = True
        flash(f"{item_to_remove} removed from your basket.")
    return redirect(url_for('basket'))

@app.route('/my_orders')
@login_required
def my_orders():
    with Session() as cursor:
        us_orders = cursor.query(Orders).filter_by(user_id=current_user.id).all()
    return render_template('my_orders.html', us_orders=us_orders)

@app.route("/my_order/<int:id>")
@login_required
def my_order(id):
    with Session() as cursor:
        us_order = cursor.query(Orders).filter_by(id=id).first()
        total_price = sum(int(cursor.query(Menu).filter_by(name=i).first().price) * int(cnt) for i, cnt in us_order.order_list.items())
    return render_template('my_order.html', order=us_order, total_price=total_price)

@app.route('/make_reservation', methods=['GET', 'POST'])
@login_required
def make_reservation():
    if request.method == "POST":
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403

        table_type = request.form['table_type']
        reserved_time_start = request.form['time']

        with Session() as cursor:
            reserved_check = cursor.query(Reservation).filter_by(type_table=table_type).count()
            user_reserved_check = cursor.query(Reservation).filter_by(user_id=current_user.id).first()

            message = f'Reservation for {reserved_time_start} table for {table_type} person successfully created!'
            if reserved_check < TABLE_NUM.get(table_type) and not user_reserved_check:
                new_reserved = Reservation(
                    type_table=table_type,
                    time_start=reserved_time_start,
                    user_id=current_user.id
                )
                cursor.add(new_reserved)
                cursor.commit()
            elif user_reserved_check:
                message = 'You can only have one active reservation'
            else:
                message = 'Unfortunately, reservation of this type of table is currently not possible'

            return render_template('make_reservation.html', message=message, csrf_token=session["csrf_token"])

    return render_template('make_reservation.html', csrf_token=session["csrf_token"])

@app.route('/admin_panel')
@login_required
def admin_panel():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))
    else:
        flash ('Welcome to the admin panel!', 'success')
    return render_template('admin_panel.html', csrf_token=session["csrf_token"])

@app.route('/reservation_check', methods=['GET', 'POST'])
@login_required
def reservation_check():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))


    if request.method == "POST":
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403


        reserv_id = request.form['reserv_id']
        with Session() as cursor:
            reservation = cursor.query(Reservation).filter_by(id=reserv_id).first()
            cursor.delete(reservation)
            cursor.commit()


    with Session() as cursor:
        all_reservations = cursor.query(Reservation).all()
        return render_template('reservation_check.html', all_reservations=all_reservations, csrf_token=session["csrf_token"])
    
@app.route('/menu_check', methods=['GET', 'POST'])
@login_required
def menu_check():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    if request.method == 'POST':
        if request.form.get("csrf_token") != session['csrf_token']:
            return "Request blocked!", 403

        position_id = request.form['pos_id']
        with Session() as cursor:
            position_obj = cursor.query(Menu).filter_by(id=position_id).first()
            if 'change_status' in request.form:
                position_obj.active = not position_obj.active
            elif 'delete_position' in request.form:
                cursor.delete(position_obj)
            cursor.commit()

    with Session() as cursor:
        all_positions = cursor.query(Menu).all()
    return render_template('check_menu.html', all_positions=all_positions, csrf_token=session["csrf_token"])
    
@app.route('/all_users')
@login_required
def all_users():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    with Session() as cursor:
        all_users = cursor.query(Users).with_entities(Users.id, Users.nickname, Users.email).all()
    return render_template('all_users.html', all_users=all_users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('csrf_token', None)
    flash('You have been logged out successfully!')
    return redirect(url_for('home'))

@app.route('/manage_positions', methods=['GET', 'POST'])
@login_required
def manage_positions():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403

        position_id = request.form.get('position_id')
        action = request.form.get('action')

        with Session() as cursor:
            position = cursor.query(Menu).filter_by(id=position_id).first()
            if position:
                if action == 'delete':
                    cursor.delete(position)
                elif action == 'toggle_active':
                    position.active = not position.active
                cursor.commit()

    with Session() as cursor:
        all_positions = cursor.query(Menu).all()
    return render_template('manage_position.html', all_positions=all_positions, csrf_token=session["csrf_token"])

@app.route('/edit_position', methods=['GET', 'POST'])
@login_required
def edit_position():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403

        position_id = request.form.get('position_id')
        name = request.form.get('name')
        ingredients = request.form.get('ingredients')
        description = request.form.get('description')
        price = request.form.get('price')
        weight = request.form.get('weight')

        with Session() as cursor:
            position = cursor.query(Menu).filter_by(id=position_id).first()
            if position:
                position.name = name
                position.ingredients = ingredients
                position.description = description
                position.price = price
                position.weight = weight
                cursor.commit()
                flash('Position updated successfully!')

    return redirect(url_for('manage_positions'))



@app.route('/support', methods=['GET', 'POST'])
@login_required
def support():
    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403

        message = request.form['message']
        with Session() as cursor:
            new_message = Position(message=message, user_id=current_user.id)
            cursor.add(new_message)
            cursor.commit()
            flash('Your message has been sent successfully!')

    return render_template('support.html', csrf_token=session["csrf_token"])

@app.route('/message_to_admin', methods=['GET', 'POST'])
@login_required
def message_to_admin():
    if request.method == 'POST':
        if request.form.get("csrf_token") != session.get("csrf_token"):
            return "Request blocked!", 403

        message_text = request.form['message']
        with Session() as cursor:
            new_message = AdminMessage(message=message_text, user_id=current_user.id)
            cursor.add(new_message)
            cursor.commit()
            flash('Your message has been sent to the admin!')

    return render_template('message_to_admin.html', csrf_token=session["csrf_token"])

@app.route('/check_my_reservation', methods=['GET', 'POST'])
@login_required
def check_my_reservation():
    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403

        with Session() as cursor:
            reservation_id = request.form.get("reserv_id")
            user_reservation = cursor.query(Reservation).filter_by(id=reservation_id, user_id=current_user.id).first()
            if user_reservation:
                cursor.delete(user_reservation)
                cursor.commit()
                flash('Your reservation has been cancelled successfully!')
            else:
                flash('You have no active reservations.')

    with Session() as cursor:
        my_reservations = (
            cursor.query(Reservation)
            .filter_by(user_id=current_user.id)
            .options(joinedload(Reservation.user))  
            .all())

    return render_template(
        'check_my_reservation.html', my_reservations=my_reservations, csrf_token=session["csrf_token"]
        )

@app.route('/about_us')
def about_us():
    return render_template('about_us.html', csrf_token=session["csrf_token"])

@app.route('/delete_order/<int:id>', methods=['POST'])
@login_required
def delete_order(id):
    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403

        with Session() as cursor:
            order = cursor.query(Orders).filter_by(id=id, user_id=current_user.id).first()
            if order:
                cursor.delete(order)
                cursor.commit()
                flash('Order deleted successfully!')
            else:
                flash('Order not found or you do not have permission to delete it.')

    return redirect(url_for('my_orders'))


@app.route('/admin_messages')
@login_required
def view_messages():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    with Session() as session:
        messages = session.query(AdminMessage).order_by(AdminMessage.id.desc()).all()
        return render_template('admin_messages.html', messages=messages)

if __name__ == '__main__':
    app.run(host="0.0.0.0")