import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)


'''
@DONE uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
'''
#db_drop_and_create_all()

## ROUTES
'''
@DONE implement endpoint
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks', methods=['GET'])
def get_drink():
    drinks_query = Drink.query.all()
    if len(drinks_query) == 0:
        abort(404)

    drinks = [drink.short() for drink in drinks_query]
    return jsonify({
        'success': True,
        'drinks': drinks
    })



'''
@DONE implement endpoint
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drinks_detail(jwt):
    try:
        drinks_query = Drink.query.all()

        if len(drinks_query) == 0:
            abort(404)

        drinks = [drink.long() for drink in drinks_query]
        return jsonify({
            'success': True,
            'drinks': drinks
        })
    except Exception as e:
        print(e)
        abort(401)


'''
@DONE implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''

@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def create_drink(jwt):
    try:
        data = request.get_json()
        if data is None:
            abort(404)
        title = data.get('title', '')
        recipe = data.get('recipe', '')
        print(title)
        print(json.dumps(recipe))
        if (title == '') or (recipe == ''):
            abort(422)

        drink = Drink(title=title, recipe=json.dumps(recipe))

        drink.insert()
        drinks = [drink.long()]
        return jsonify({
            'success': True,
            'drinks': drinks
        })
    except Exception as e:
        print(e)
        abort(401)




'''
@DONE implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def edit_drink(jwt, drink_id):

    try:

        drink = Drink.query.filter(Drink.id == drink_id).one_or_none()
        if drink == None:
            abort(404)

        data = request.get_json()
        new_title = data.get('title', '')
        print(new_title)
        new_recipe = data.get('recipe', '')
        print(new_recipe)

        if (new_recipe == '') or (new_title == ''):
            abort(422)

        drink.title = new_title
        drink.recipe = json.dumps(new_recipe)

        drink.update()

        drinks = [drink.long()]

        return jsonify({
            'success': True,
            'drinks': drinks
        })
    except Exception as e:
        print(e)
        abort(401)

'''
@DONE implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''

@app.route('/drinks/<int:drink_id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(jwt, drink_id):
    try:

        drink = Drink.query.filter(Drink.id == drink_id).one_or_none()

        if drink is None:
            abort(404)

        id = drink.id
        drink.delete()
        drinks = [drink.long() for drink in Drink.query.all()]
        return jsonify({
            'success': True,
            'delete': id,
            'drinks': drinks
        })
    except Exception as e:
        print(e)
        abort(401)


## Error Handling
'''
Example error handling for unprocessable entity
'''
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
                    "success": False,
                    "error": 422,
                    "message": "unprocessable"
                    }), 422

'''
@DONE implement error handlers using the @app.errorhandler(error) decorator
    each error handler should return (with approprate messages):
             jsonify({
                    "success": False,
                    "error": 404,
                    "message": "resource not found"
                    }), 404

'''


'''
@TODO implement error handler for 404
    error handler should conform to general task above
'''

@app.errorhandler(404)
def not_found(error):
    return jsonify({
                    "success": False,
                    "error": 404,
                    "message": "resource not found"
                    }), 404

'''
@TODO implement error handler for AuthError
    error handler should conform to general task above
'''
@app.errorhandler(AuthError)
def auth_error(error):
    error_details = error.error
    error_status_code = error.status_code 

    return jsonify({
                    "success": False,
                    "error": error_status_code,
                    "message": error_details['description']
                    }), error_status_code
