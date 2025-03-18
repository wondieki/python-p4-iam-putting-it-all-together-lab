from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        try:
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()

            if not username or not password:
                return {"error": "Invalid input"}, 422

            user = User(
                username=username,
                bio=data.get('bio', '').strip(),
                image_url=data.get('image_url', '').strip()
            )
            user.password_hash = password
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(), 201
        except IntegrityError:
            db.session.rollback()
            return {"error": "Username already exists."}, 422
        except Exception as e:
            return {"error": str(e)}, 400

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404

        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        request_json = request.get_json()
        username = request_json.get('username')
        password = request_json.get('password')

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {'error': 'Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        if 'user_id' not in session or session.get('user_id') is None:
            return {'error': 'Unauthorized'}, 401

        session['user_id'] = None
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404

        return [recipe.to_dict() for recipe in user.recipes], 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        request_json = request.get_json()
        title = request_json.get('title', '').strip()
        instructions = request_json.get('instructions', '').strip()
        minutes_to_complete = request_json.get('minutes_to_complete')

        if not title or not instructions or not minutes_to_complete:
            return {"error": "Invalid input"}, 422

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id,
            )
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(), 201

        except ValueError as e:
            return {"error": str(e)}, 422

        except IntegrityError:
            db.session.rollback()
            return {"error": "Unprocessable Entity"}, 422

        except Exception as e:
            db.session.rollback()
            return {"error": f"Unexpected error: {str(e)}"}, 500

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)