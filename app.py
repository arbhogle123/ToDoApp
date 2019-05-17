from flask_mongoengine import MongoEngine
from wtforms.validators import Email, Length, InputRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, render_template, request, redirect, jsonify, url_for ,session
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from pusher import Pusher
import json
import urllib
import pymongo



app = Flask(__name__)

app.config['MONGODB_SETTINGS'] = {
    'db': 'logindetails',
    'host': 'mongodb://quantiphi:'+urllib.parse.quote('Quant@123',safe='')+'@ds155616.mlab.com:55616/todolist'
}


db = MongoEngine(app)
app.config['SECRET_KEY'] = 'IAMIRONMAN'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

# pymongo
myclient = pymongo.MongoClient('mongodb://quantiphi:'+urllib.parse.quote('Quant@123',safe='')+'@ds155616.mlab.com:55616/todolist')
mydb = myclient["todolist"]
mycol = mydb["list"]


class User(UserMixin, db.Document):
    meta = {'collection': 'users'}
    email = db.StringField(max_length=30)
    password = db.StringField()

@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()


class RForm(Form):
    email = StringField('Email', validators=[InputRequired(),Email(message='Invalid email'), Length(max=30)])
    password = PasswordField('Password', validators=[InputRequired(),validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')


class LForm(Form):
    email = StringField('Registered-Email', validators=[InputRequired(),Email(message='Invalid email'), Length(max=30)])
    password = PasswordField('Password', validators=[InputRequired()])


taskList = []


pusher = Pusher(
      app_id='782456',
      key='581bad5eae78e529bba7',
      secret='723f0cddc8aecc2f0ea4',
      cluster='ap2',
      ssl=True
    )


@app.route("/", methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated == True:
        return redirect(url_for('home'))
    form = LForm(request.form)
    if request.method == 'POST':
        if form.validate():
            check_user = User.objects(email=form.email.data).first()
            if check_user:
                if check_password_hash(check_user['password'], form.password.data):
                    login_user(check_user)
                    return render_template('home.html', name=current_user.email)

        return render_template('index.html', form=form,msg="Invalid Username-Password")

    return render_template('index.html',form=form, msg="")


@app.route("/signin",  methods=['GET', 'POST'])
def register():
    form = RForm(request.form)
    if request.method == 'POST':
        if form.validate():
            existing_user = User.objects(email=form.email.data).first()
            if existing_user is None:
                hashpass = generate_password_hash(form.password.data, method='sha256')
                hey = User(form.email.data, hashpass).save()
                login_user(hey)
                return redirect(url_for('index'))

        return render_template("signin.html",form=form, msg="That email already Exists!!")

    return render_template('signin.html', form=form,msg="")


@app.route("/home")
@login_required
def home():
    global taskList
    if mycol.find({'user_mail': current_user.email}).count() == 0:
        return render_template("home.html", list="",name=current_user.email)
    pyobj = mycol.find({'user_mail': current_user.email}, {'_id': 0, 'list': 1})
    for x in pyobj:
        list = x['list']
    taskList = list
    print(list)
    print(taskList)
    return render_template("home.html", list=list,name=current_user.email)


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    session.pop('username', None)
    logout_user()
    return redirect(url_for('index'))


# endpoint for storing todo item
@app.route('/add-todo', methods=['POST'])
def addTodo():
    global taskList
    data = json.loads(request.data)  # load JSON data from request
    pusher.trigger('todo', 'item-added', data)  # trigger `item-added` event on `todo` channel
    task = {
        '_id': data.get('id'),
        'value': data.get('value'),
        'completed': data.get('completed')
    }
    print(taskList)
    taskList.append(task)
    print(taskList)
    mycol.update_one(({'user_mail': current_user.email}), {"$set": {'user_mail': current_user.email, 'list': taskList}}, upsert=bool(1))
    return jsonify(data)


@app.route('/modify-todo', methods=['POST'])
def modifyTodo():
    global taskList
    data = json.loads(request.data)  # load JSON data from request
    print(data.get('value'))
    if data.get('value') == "":
        pusher.trigger('todo', 'item-removed', {'_id': data.get('id')})
        for x in range(len(taskList)):
            if taskList[x].get('_id') == data.get('id'):
                taskList.pop(x)
                break
    else:
        print('hii')
        for x in range(len(taskList)):
            if taskList[x].get('_id') == data.get('id'):
                taskList[x]['value'] = data.get('value')
                break
    print(taskList)
    mycol.update_one(({'user_mail': current_user.email}), {"$set": {'list': taskList}})
    return jsonify(data)


# endpoint for deleting todo item
@app.route('/remove-todo/<item_id>')
def removeTodo(item_id):
    global taskList
    data = {'_id': item_id}
    pusher.trigger('todo', 'item-removed', data)
    for x in range(len(taskList)):
        if taskList[x].get('_id') == item_id:
            taskList.pop(x)
            break
    print(taskList)
    mycol.update_one(({'user_mail': current_user.email}), {"$set": {'list': taskList}})
    return jsonify(data)


# endpoint for updating todo item
@app.route('/update-todo/<item_id>', methods=['POST'])
def updateTodo(item_id):
    global taskList
    data = {
        '_id': item_id,
        'completed': json.loads(request.data).get('completed', 0)
    }
    pusher.trigger('todo', 'item-updated', data)
    for x in range(len(taskList)):
        if taskList[x].get('_id') == item_id:
            taskList[x].update({'completed': data['completed']})
            break
    print(taskList)
    mycol.update_one(({'user_mail': current_user.email}), {"$set": {'list': taskList}})
    return jsonify(data)


if __name__ == "__main__":
    app.run(debug=True)
