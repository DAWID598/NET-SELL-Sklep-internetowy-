from flask import Flask
from flask import render_template
from flask import request
from flask import flash
from flask import url_for
from flask import g
from flask import current_app
from flask import redirect
from flask import session
from datetime import date
import sqlite3
import random
import string
import hashlib
import binascii




app = Flask(__name__)


app.config['SECRET_KEY'] = "Klucz"

DATABASE = 'C:/Users/Dawid/Desktop/netsellnetsell/Baza_danych/netsell.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

      
class UserPass:

    def __init__(self, user='', password=''):
        self.user = user
        self.password = password
        self.is_valid = False
        self.is_admin = False  


    def hash_password(self):
        """Hash a password for storing."""
        # the value generated using os.urandom(60)
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')
    
    def verify_password(self, stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'),  100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def get_random_user_pasword(self):
        random_user = ''.join(random.choice(string.ascii_lowercase)for i in range(3))
        self.user = random_user

        password_characters = string.ascii_letters #+ string.digits + string.punctuation
        random_password = ''.join(random.choice(password_characters)for i in range(3))
        self.password = random_password

    def login_user(self):

        db = get_db()
        sql_statement = 'select id, name, email, password, is_active, is_admin from users where email=?'
        cur = db.execute(sql_statement, [self.user])
        user_record = cur.fetchone()

        if user_record != None and self.verify_password(user_record['password'], self.password):
            return user_record
        else:
            self.user = None
            self.password = None
            return None   


    def get_user_info(self):
        db = get_db()
        sql_statement = 'select name, email, is_active, is_admin from users where email=?'
        cur = db.execute(sql_statement, [self.user])
        db_user = cur.fetchone()

        if db_user == None:
            self.is_valid = False
            self.is_admin = False
    
        elif db_user['is_active']!=1:
            self.is_valid = False
            self.is_admin = False
        
        else:
            self.is_valid = True
            self.is_admin = db_user['is_admin']
            


class NewsleterSubscriber:
    def __init__(self, email=''):
        self.email = email


@app.route('/init_app')
def init_app():

    # check if there are users defined (at least one active admin required)
    db = get_db()
    sql_statement = 'select count(*) as cnt from users where is_active and is_admin;'
    cur = db.execute(sql_statement)
    active_admins = cur.fetchone()

    if active_admins!=None and active_admins['cnt']>0:
        flash('Wszystko okej, aplikacja ma już utworzone testowe konto admina.')
        return redirect(url_for('home'))

    # if not - create/update admin account with a new password and admin privileges, display random username
    user_pass = UserPass()
    user_pass.get_random_user_pasword()
    sql_statement = '''insert into users(name, surname, email, password, is_active, is_admin)
                       values(?,?,?,?,True, True);'''
    db.execute(sql_statement, [user_pass.user, 'Kowalski', 'rdawid239@gmail.com', user_pass.hash_password()])
    db.commit()
    print('Użytkownik testowy z loginem: rdawid239@gmail.com i hasłem: {} został utworzony'.format(user_pass.password))
    flash('Użytkownik testowy z loginem: rdawid239@gmail.com i hasłem: {} został utworzony'.format(user_pass.password))
    return redirect(url_for('home'))




@app.route('/login', methods=['GET','POST'])
def login():

    if 'user' in session:
        return redirect(url_for('home'))
   


    if request.method == 'GET':
        return render_template("login.html")
    else:
        user_name = '' if 'user_name' not in request.form else request.form['user_name']
        user_pass = '' if 'user_pass' not in request.form else request.form['user_pass']

        login = UserPass(user_name, user_pass)
        login_record = login.login_user()

        if login_record != None:
            session['user'] = user_name
            flash('Zostałeś poprawnie zalogowany, witaj: {}'.format(user_name))
            return redirect(url_for('home'))
        else:
            flash('Niepoprawny login lub hasło. Spróbuj ponownie.')
            return render_template("login.html")

@app.route('/logout')
def logout():

    if 'user' in session:
        session.pop('user', None)
        flash('Zostałeś poprawnie wylogowany.')
    return redirect(url_for('home'))


@app.route("/", methods=['GET','POST'])
def home():
    login = UserPass(session.get('user'))
    login.get_user_info()
    db = get_db()
    message = None
    newsletter = {}
    if request.method =='GET':
      return render_template('home.html', login=login, newsletter=newsletter)
    else:
        newsletter['email'] = '' if not 'email' in request.form else request.form['email']
        cursor = db.execute('select count(*) as cnt from newsletter where email = ?', [newsletter['email']])
        record = cursor.fetchone()
        is_newsletter_email_unique = (record['cnt'] == 0)
        if newsletter['email'] == '':
            message = 'Pole e-mail nie może być puste.'
        elif not is_newsletter_email_unique:
            message = 'Użytkownik z tym adresem e-mail: {} jest już zapisany do naszego newslettera.'.format(newsletter['email'])
    if not message:
        sql_statement = '''insert into newsletter(email)
                          values(?);'''
        db.execute(sql_statement, [newsletter['email']])
        db.commit()
        flash('Adres e-mail {} został dodany do naszego newslettera.'.format(newsletter['email']))
        return redirect(url_for('home', login=login, newsletter=newsletter))
    else:
        flash('{}'.format(message))
        return render_template('home.html', login=login, newsletter=newsletter)

@app.route("/help")
def help():
    login = UserPass(session.get('user'))
    login.get_user_info()
    return render_template('help.html', login=login)



@app.route('/users')
def users():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))


    db = get_db()
    sql_command = 'select id, name, surname, email, is_admin, is_active from users;'
    cur = db.execute(sql_command)
    users = cur.fetchall()

    return render_template('users.html', users=users, login=login)


@app.route('/user_status_change/<action>/<user_name>')
def user_status_change(action, user_name):
    if not 'user' in session:
        return redirect(url_for('login'))
    login = session['user']
    print(login)
    
    db = get_db()

    if action == 'active':
        db.execute("""update users set is_active = (is_active + 1) % 2 
                      where email = ? and email <> ?""",
                      [user_name, login])
        db.commit()
    elif action == 'admin':
        db.execute("""update users set is_admin = (is_admin + 1) % 2 
                      where email = ? and email <> ?""",
                      [user_name, login])
        db.commit()

    return redirect(url_for('users'))



@app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
def edit_user(user_name):
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    db = get_db()
    cur = db.execute('select name, surname, email from users where email = ?', [user_name])
    user = cur.fetchone()
    message = None

    if user == None:
        #flash('Nie ma takiego użytkownika:')
        return redirect(url_for('users'))

    if request.method == 'GET':
        return render_template('edit_user.html', user=user)
    else:
        new_email = '' if 'email' not in request.form else request.form["email"]
        new_name = '' if 'name' not in request.form else request.form['name']
        new_surname = '' if 'surname' not in request.form else request.form['surname']
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']
        confirm_password = '' if 'confirm_user_pass' not in request.form else request.form['confirm_user_pass']

       
        if new_password != confirm_password:
            flash('Hasła nie pasują do siebie. Proszę wprowadzić je ponownie.')
            return redirect('edit_user')
   

        if new_name != user['name']:
            sql_statement = "update users set name = ? where email = ?"
            db.execute(sql_statement, [new_name, user_name])
            db.commit()
            flash('Imię zostało zmienione.')

      
        if new_surname != user['surname']:
           sql_statement = "update users set surname = ? where email = ?"
           db.execute(sql_statement, [new_surname, user_name])
           db.commit()
           flash('Nazwisko zostało zmienione.')


        if new_password != '':
            user_pass = UserPass(user_name, new_password)
            sql_statement = "update users set password = ?  where email = ?"
            db.execute(sql_statement, [user_pass.hash_password(), user_name])
            db.commit()          
            flash('Hasło zostało zmienione.')    

        if new_email != user['email']:
            sql_statement = "update users set email = ? where email = ?"
            db.execute(sql_statement, [new_email, user_name])
            db.commit()
            flash('Adres e-mail został zmieniony.')
       

        return redirect(url_for('users'))


@app.route('/user_panel')
def user_panel():
    
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))
    
    info = session['user']

    db = get_db()
    sql_command = 'select name, surname, email from users where email = ?;'
    cur = db.execute(sql_command, [info])
    users = cur.fetchone()

    return(render_template('user_panel.html', users=users, login=login))



@app.route('/edit_yourself', methods=['GET', 'POST'])
def edit_yourself():
    login = UserPass(session.get('user'))
    login.get_user_info()
    info = session['user']
    if not login.is_valid:
        return redirect(url_for('login'))
    db = get_db()
    cur = db.execute('select name, surname, email from users where email = ?', [info])
    user = cur.fetchone()
    message = None
  
    if user == None:
            flash('Nie ma takiego użytkownika:')
            return redirect(url_for('user_panel.html'))

    if request.method == 'GET':
        return render_template('edit_yourself.html', info=info, user=user)
    else:
        new_name = '' if 'name' not in request.form else request.form['name']
        new_surname = '' if 'surname' not in request.form else request.form['surname']
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']
        confirm_password = '' if 'confirm_user_pass' not in request.form else request.form['confirm_user_pass']


        if new_password != confirm_password:
            flash('Hasła nie pasują do siebie. Proszę wprowadzić je ponownie.')
            return redirect('edit_yourself')
        
   
        if new_name != user['name']:
            sql_statement = "update users set name = ? where email = ?"
            db.execute(sql_statement, [new_name, info])
            db.commit()
            flash('Imię zostało zmienione.')
           

        if new_surname != user['surname']:
           sql_statement = "update users set surname = ? where email = ?"
           db.execute(sql_statement, [new_surname, info])
           db.commit()
           flash('Nazwisko zostało zmienione.')
        

        if new_password != '':
            user_pass = UserPass(info, new_password)
            sql_statement = "update users set password = ?  where email = ?"
            db.execute(sql_statement, [user_pass.hash_password(), info])
            db.commit()          
            flash('Hasło zostało zmienione.')           

        return redirect(url_for('edit_yourself'))



@app.route('/delete_user/<user_name>')
def delete_user(user_name):
   
   if not 'user' in session:
        return redirect(url_for('login'))
   login = session['user']

   db = get_db()
   sql_statement = "delete from users where email = ? and email <> ?"
   db.execute(sql_statement, [user_name, login])
   db.commit()
   

   return redirect(url_for('users'))


@app.route('/register', methods = ['GET', 'POST'])
def register():
        
    if 'user' in session:
        return redirect(url_for('home'))
   

    db = get_db()
    message = None
    user = {}

    if request.method =='GET':
        return render_template('register.html', user=user)
    else:
        user['name'] = '' if not 'name' in request.form else request.form['name']
        user['surname'] = '' if not 'surname' in request.form else request.form['surname']
        user['user_name'] = '' if not 'user_name' in request.form else request.form['user_name']
        user['user_pass'] = '' if not 'user_pass' in request.form else request.form['user_pass']
        user['confirm_password'] = '' if 'confirm_password' not in request.form else request.form['confirm_password']

        
        cursor = db.execute('select count(*) as cnt from users where email = ?', [user['user_name']])
        record = cursor.fetchone()
        is_user_email_unique = (record['cnt'] == 0)

        
    
        if user['user_name'] == '':
            message = 'Pole e-mail nie może być puste.'
        elif user['name'] == '':
            message = 'Pole Imię nie może być puste.'
        elif user['surname'] == '':
            message = 'Pole Nazwisko nie może być puste.'
        elif user['user_pass'] == '':
            message = 'Pole Hasło nie może być puste.'
        elif user['user_pass'] != user['confirm_password']:
            message = 'Pole Hasło i Powtórz Hasło muszą być takie same !'
        elif not is_user_email_unique:
            message = 'Użytkownik z tym adresem e-mail: {} jest już zarejestrowany.'.format(user['user_name'])

        if not message:
            user_pass = UserPass(user['user_name'], user['user_pass'])          
            password_hash = user_pass.hash_password()
            sql_statement = '''insert into users(name, surname, email, password, is_active, is_admin)
                          values(?,?,?,?, True, False);''' 
            db.execute(sql_statement, [user['name'], user['surname'], user['user_name'], password_hash])
            db.commit()
            flash('Użytkownik {} został zarejestrowany.'.format(user['user_name']))
            return redirect(url_for('home'))
        else:
            flash('Popraw następujący błąd: {}'.format(message))
            return render_template('register.html', user=user)

@app.route('/laptopy')
def laptopy():
    login = UserPass(session.get('user'))
    login.get_user_info()
    db=get_db()
    sql_command = 'select * from asortyment where kategoria = "Laptopy"'
    cur = db.execute(sql_command)
    laptopy = cur.fetchall()
    return render_template('laptops.html', login=login, laptopy=laptopy)

@app.route('/telefony')
def telefony():
    login = UserPass(session.get('user'))
    login.get_user_info()
    db=get_db()
    sql_command = 'select * from asortyment where kategoria = "Telefony"'
    cur = db.execute(sql_command)
    telefony = cur.fetchall()
    return render_template('smartphones.html', login=login, telefony=telefony)

@app.route('/konsole')
def konsole():
    login = UserPass(session.get('user'))
    login.get_user_info()
    db=get_db()
    sql_command = 'select * from asortyment where kategoria = "Konsole"'
    cur = db.execute(sql_command)
    konsole = cur.fetchall()
    return render_template('consoles.html', login=login, konsole=konsole)


@app.route('/admin_panel')
def admin_panel():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    
    info = session['user']

    db = get_db()
    sql_command = 'select name from users where email = ?;'
    cur = db.execute(sql_command, [info])
    users = cur.fetchone()

    return render_template('admin_panel.html', users=users, login=login)

@app.route('/show_assortment')
def show_assortment():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    db = get_db()
    sql_command = 'select id, zdjecie, kategoria, nazwa, procesor, ekran, karta_graficzna, pamiec_ram, dysk, cena, liczba_sztuk from asortyment;'
    cur = db.execute(sql_command)
    assortment = cur.fetchall()

    return render_template('show_assortment.html', assortment=assortment, login=login)


@app.route('/delete_assortment/<int:assortment_id>')
def delete_assortment(assortment_id):
   
   if not 'user' in session:
        return redirect(url_for('login'))
   login = session['user']
   db = get_db()
   sql_statement = "delete from asortyment where id = ?"
   db.execute(sql_statement, [assortment_id])
   db.commit()
   

   return redirect(url_for('show_assortment'))


@app.route('/edit_assortment/<int:assortment_id>', methods=['GET', 'POST'])
def edit_assortment(assortment_id):
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    db = get_db()
    cur = db.execute('select id, zdjecie, kategoria, nazwa, procesor, ekran, karta_graficzna, pamiec_ram, dysk, cena, liczba_sztuk from asortyment where id = ?', [assortment_id])
    laptop = cur.fetchone()
    

    if laptop == None:
        flash('Nie ma takiego rekordu:')
        return redirect(url_for('show_assortment'))
    if request.method == 'GET':
        return render_template('edit_assortment.html', laptop=laptop)
    
    else:
        new_zdjecie = '' if 'zdjecie' not in request.form else request.form["zdjecie"]
        new_kategoria = '' if 'kategoria' not in request.form else request.form['kategoria']
        new_nazwa = '' if 'nazwa' not in request.form else request.form['nazwa']
        new_procesor = '' if 'procesor' not in request.form else request.form['procesor']
        new_ekran = '' if 'ekran' not in request.form else request.form['ekran']
        new_karta_graficzna = '' if 'karta_graficzna' not in request.form else request.form['karta_graficzna']
        new_pamiec_ram = '' if 'pamiec_ram' not in request.form else request.form['pamiec_ram']
        new_dysk = '' if 'dysk' not in request.form else request.form['dysk']
        new_cena = '' if 'cena' not in request.form else request.form['cena']
        new_liczba_sztuk = '' if 'liczba_sztuk' not in request.form else request.form['liczba_sztuk']

        if new_zdjecie != laptop['zdjecie']:
            sql_statement = "update asortyment set zdjecie = ? where id = ?"
            db.execute(sql_statement, [new_zdjecie, assortment_id])
            db.commit()
            flash('Zdjęcie zostało zmienione.')

        if new_kategoria != laptop['kategoria']:
            sql_statement = "update asortyment set kategoria = ? where id = ?"
            db.execute(sql_statement, [new_kategoria, assortment_id])
            db.commit()
            flash('Kategoria została zmieniona.')

        if new_nazwa != laptop['nazwa']:
            sql_statement = "update asortyment set nazwa = ? where id = ?"
            db.execute(sql_statement, [new_nazwa, assortment_id])
            db.commit()
            flash('Nazwa została zmieniona.')
        
        if new_procesor != laptop['procesor']:
            sql_statement = "update asortyment set procesor = ? where id = ?"
            db.execute(sql_statement, [new_procesor, assortment_id])
            db.commit()
            flash('Pole procesor zostało zmienione.')

        if str(new_ekran) != str(laptop['ekran']):
            sql_statement = "update asortyment set ekran = ? where id = ?"
            db.execute(sql_statement, [new_ekran, assortment_id])
            db.commit()
            flash('Pole ekran zostało zmienione.')


        if new_karta_graficzna != laptop['karta_graficzna']:
            sql_statement = "update asortyment set karta_graficzna = ? where id = ?"
            db.execute(sql_statement, [new_karta_graficzna, assortment_id])
            db.commit()
            flash('Pole karta graficzna zostało zmienione.')


        if str(new_pamiec_ram) != str(laptop['pamiec_ram']):
            sql_statement = "update asortyment set pamiec_ram = ? where id = ?"
            db.execute(sql_statement, [new_pamiec_ram, assortment_id])
            db.commit()
            flash('Pole pamiec ram zostało zmienione.')


        if str(new_dysk) != str(laptop['dysk']):
            sql_statement = "update asortyment set dysk = ? where id = ?"
            db.execute(sql_statement, [new_dysk, assortment_id])
            db.commit()
            flash('Pole dysk zostało zmienione.')


        if str(new_cena) != str(laptop['cena']):
            sql_statement = "update asortyment set cena = ? where id = ?"
            db.execute(sql_statement, [new_cena, assortment_id])
            db.commit()
            flash('Pole cena zostało zmienione.')


        if str(new_liczba_sztuk) != str(laptop['liczba_sztuk']):
            sql_statement = "update asortyment set liczba_sztuk = ? where id = ?"
            db.execute(sql_statement, [new_liczba_sztuk, assortment_id])
            db.commit()
            flash('Pole liczba sztuk zostało zmienione.')

        return redirect(url_for('show_assortment'))

        
	
@app.route('/add_assortment', methods=['GET', 'POST'])
def add_assortment():
        
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    message = None
    laptop = {}

    if request.method =='GET':
        return render_template('add_assortment.html', laptop=laptop)
    else:
        laptop['zdjecie'] = '' if 'zdjecie' not in request.form else request.form["zdjecie"]
        laptop['kategoria'] = '' if 'kategoria' not in request.form else request.form["kategoria"]
        laptop['nazwa'] = '' if 'nazwa' not in request.form else request.form['nazwa']
        laptop['procesor'] = '' if 'procesor' not in request.form else request.form['procesor']
        laptop['ekran'] = '' if 'ekran' not in request.form else request.form['ekran']
        laptop['karta_graficzna'] = '' if 'karta_graficzna' not in request.form else request.form['karta_graficzna']
        laptop['pamiec_ram'] = '' if 'pamiec_ram' not in request.form else request.form['pamiec_ram']
        laptop['dysk'] = '' if 'dysk' not in request.form else request.form['dysk']
        laptop['cena'] = '' if 'cena' not in request.form else request.form['cena']
        laptop['liczba_sztuk'] = '' if 'liczba_sztuk' not in request.form else request.form['liczba_sztuk']

        if not message:
            sql_statement = '''insert into asortyment(zdjecie, kategoria, nazwa, procesor, ekran, karta_graficzna, pamiec_ram, dysk, cena, liczba_sztuk)
                          values(?,?,?,?,?,?,?,?,?,?);''' 
            db.execute(sql_statement, [laptop['zdjecie'], laptop['kategoria'], laptop['nazwa'], laptop['procesor'], laptop['ekran'], laptop['karta_graficzna'], laptop['pamiec_ram'], laptop['dysk'], laptop['cena'], laptop['liczba_sztuk']])
            db.commit()
            flash('Przedmiot {} został dodany do asortymentu.'.format(laptop['nazwa']))
            return redirect(url_for('show_assortment'))
        else:
            flash('Popraw następujący błąd: {}'.format(message))
            return render_template('add_assortment.html', laptop=laptop)
 	
 	   
#@app.route('/shopping_cart')
#def shopping_cart():
    #login = UserPass(session.get('user'))
    #login.get_user_info()
    #return render_template('shopping_cart.html', login=login)
        
@app.route('/shopping_cart')
def shopping_cart():
        login = UserPass(session.get('user'))
        login.get_user_info()
        if not login.is_valid:
         return redirect(url_for('login'))
        info = session['user']
        db = get_db()
        # Pobierz produkty w koszyku
        cur = db.execute("SELECT * FROM koszyk WHERE wlasciciel=?", [info])
        cart = cur.fetchall()

        # Pobierz łączną wartość koszyka
        total_value = sum(item['wartosc'] for item in cart)

        return render_template('shopping_cart.html', cart=cart, total_value=total_value)


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    login = UserPass(session.get('user'))
    login.get_user_info()
    db = get_db()
    info = session['user']
    cur = db.execute('select * from asortyment where id = ?', [product_id])
    product = cur.fetchone()
    if product:
            # Dodaj produkt do koszyka
            cur= db.execute("INSERT INTO koszyk (produkt_id, nazwa, wlasciciel, wartosc, ilosc) VALUES (?, ?, ?, ?, ?)",
                           (product['id'],product['nazwa'], info, product['cena'], 1))
            db.commit()
            flash('Dodano do koszyka!')
    else:
            flash('Produkt nie istnieje!')

    return redirect(request.referrer)

@app.route('/update_cart/<string:product_name>', methods=['POST'])
def update_cart(product_name):
        db = get_db()
        # Pobierz informacje o produkcie
        cur = db.execute('select * from asortyment where nazwa = ?', [product_name])
        product = cur.fetchone()
        if product:
            new_quantity = int(request.form.get('quantity', 1))
            # Aktualizuj ilość produktu w koszyku
            cur = db.execute("UPDATE koszyk SET wartosc = ?, ilosc = ? WHERE nazwa = ? ",
                         ((product['cena'] * new_quantity), new_quantity, product_name))
            db.commit()
            flash('Koszyk zaktualizowany!')
        else:
            flash('Produkt nie istnieje!')
        return redirect(url_for('shopping_cart'))


@app.route('/remove_from_cart<product_id>')
def remove_from_cart(product_id):
        db = get_db()
        # Usuń produkt z koszyka
        cur=db.execute("DELETE FROM koszyk WHERE id = ?", (product_id,))
        db.commit()
        flash('Produkt usunięty z koszyka!')

        return redirect(url_for('shopping_cart'))


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))

    info = session['user']
    db = get_db()

    # Pobierz produkty w koszyku
    cur = db.execute("SELECT * FROM koszyk WHERE wlasciciel=?", [info])
    cart = cur.fetchall()

    # Pobierz łączną wartość koszyka
    total_value = sum(item['wartosc'] for item in cart)

    if request.method == 'POST':
        user = {}
        message = None
        user['phone_number'] = request.form.get('phone_number', '')
        user['name'] = request.form.get('name', '')
        user['surname'] = request.form.get('surname', '')
        user['address'] = request.form.get('address', '')
        user['post_code'] = request.form.get('post_code', '')

        if not user['phone_number']:
            message = 'Pole Numer telefonu nie może być puste.'
        elif not user['name']:
            message = 'Pole Imię nie może być puste.'
        elif not user['surname']:
            message = 'Pole Nazwisko nie może być puste.'
        elif not user['address']:
            message = 'Pole Adres nie może być puste.'
        elif not user['post_code']:
            message = 'Pole Kod-Pocztowy nie może być puste.'

        if not message:
            # Tworzenie zamówienia
            order_details = []

            for item in cart:
                name = item['nazwa']
                quantity = item['ilosc']
                order_details.append(f'{name} (ilość: {quantity})')

                product = db.execute("SELECT * FROM asortyment WHERE nazwa=?", [name]).fetchone()
                if product and product['liczba_sztuk'] >= quantity:
                    # Zmniejsz stan magazynowy
                    db.execute("UPDATE asortyment SET liczba_sztuk=? WHERE nazwa=?", [product['liczba_sztuk'] - quantity, name])
                    db.commit()
                else:
                    flash(f"Niewystarczający stan magazynowy dla produktu: {name}")
                    return redirect(url_for('shopping_cart'))

            order_description = ', '.join(order_details)

            sql_statement = '''INSERT INTO zamowienie 
                               (email, numer_telefonu, imie, nazwisko, adres, kod_pocztowy, tresc_zamowienia, wartosc_zamowienia, zrealizowane)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0);'''
            db.execute(sql_statement, [info, user['phone_number'], user['name'], user['surname'], user['address'], user['post_code'], order_description, total_value])
            db.commit()

            order_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

            # Wyczyszczenie koszyka
            db.execute("DELETE FROM koszyk WHERE wlasciciel=?", [info])
            db.commit()

            flash('Zamówienie zostało przyjęte do realizacji!')
            return redirect(url_for('checkout_finish', total_value=total_value, order_id=order_id))
        else:
            flash('Popraw następujący błąd: {}'.format(message))

    return render_template('checkout.html', cart=cart, total_value=total_value)


@app.route('/orders')
def orders():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))
    info = session['user']
    db = get_db()
    cur = db.execute("select id, data_zamowienia, numer_telefonu, imie, nazwisko, adres, kod_pocztowy, tresc_zamowienia, wartosc_zamowienia, zrealizowane from zamowienie where email = ?", [info])
    orders = cur.fetchall()
    return render_template('orders.html', orders=orders, login=login)

@app.route('/checkout_finish/<float:total_value>/<int:order_id>')
def checkout_finish(total_value, order_id):
     login = UserPass(session.get('user'))
     login.get_user_info()
     if not login.is_valid:
        return redirect(url_for('login'))
     return render_template('checkout_finish.html', login=login, total_value=total_value, order_id=order_id)

@app.route('/admin_orders')
def admin_orders():
     login = UserPass(session.get('user'))
     login.get_user_info()
     if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
     db = get_db()
     cur = db.execute("select id, data_zamowienia, email, numer_telefonu, imie, nazwisko, adres, kod_pocztowy, tresc_zamowienia, wartosc_zamowienia, zrealizowane from zamowienie")
     orders = cur.fetchall()
     return render_template('admin_orders.html', login=login, orders=orders)


@app.route('/order_status_change/<action>/<order_id>')
def order_status_change(action, order_id):
    if not 'user' in session:
        return redirect(url_for('login'))
    login = session['user']
    
    db = get_db()

    if action == 'zrealizowane':
        db.execute("""update zamowienie set zrealizowane = (zrealizowane + 1) % 2 
                      where id = ?""",
                      [order_id])
        db.commit()

    return redirect(url_for('admin_orders'))


@app.route('/delete_order/<order_id>')
def delete_order(order_id):
   
   if not 'user' in session:
        return redirect(url_for('login'))
   login = session['user']

   db = get_db()
   sql_statement = "delete from zamowienie where id = ?"
   db.execute(sql_statement, [order_id])
   db.commit()
   return redirect(url_for('admin_orders'))