import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
import json
from api import app, db, User, Organisation


class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        with app.app_context():
            db.create_all()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def register_user(self):
        return self.app.post('/auth/register', data=json.dumps({
            "firstName": "John",
            "lastName": "Doe",
            "email": "john.doe@example.com",
            "password": "password123",
            "phone": "1234567890"
        }), content_type='application/json')

    def login_user(self):
        return self.app.post('/auth/login', data=json.dumps({
            "email": "john.doe@example.com",
            "password": "password123"
        }), content_type='application/json')

    def test_register_user(self):
        response = self.register_user()
        self.assertEqual(response.status_code, 201)

    def test_login_user(self):
        self.register_user()
        response = self.login_user()
        data = json.loads(response.get_data())
        self.assertEqual(response.status_code, 200)
        self.assertIn('accessToken', data['data'])

    def test_get_user(self):
        self.register_user()
        login_response = self.login_user()
        token = json.loads(login_response.get_data())['data']['accessToken']

        response = self.app.get('/api/users/john.doe@example.com', headers={
            'x-access-tokens': token
        })
        self.assertEqual(response.status_code, 200)

    def test_create_organisation(self):
        self.register_user()
        login_response = self.login_user()
        token = json.loads(login_response.get_data())['data']['accessToken']

        response = self.app.post('/api/organisations', data=json.dumps({
            "name": "New Organisation",
            "description": "Description of the organisation"
        }), headers={
            'x-access-tokens': token
        }, content_type='application/json')

        self.assertEqual(response.status_code, 201)

    def test_get_organisations(self):
        self.register_user()
        login_response = self.login_user()
        token = json.loads(login_response.get_data())['data']['accessToken']

        self.app.post('/api/organisations', data=json.dumps({
            "name": "New Organisation",
            "description": "Description of the organisation"
        }), headers={
            'x-access-tokens': token
        }, content_type='application/json')

        response = self.app.get('/api/organisations', headers={
            'x-access-tokens': token
        })
        self.assertEqual(response.status_code, 200)

    def test_add_user_to_organisation(self):
        self.register_user()
        login_response = self.login_user()
        token = json.loads(login_response.get_data())['data']['accessToken']

        # Create a new organisation
        org_response = self.app.post('/api/organisations', data=json.dumps({
            "name": "New Organisation",
            "description": "Description of the organisation"
        }), headers={
            'x-access-tokens': token
        }, content_type='application/json')
        org_id = json.loads(org_response.get_data())['data']['orgId']

        # Create a new user
        user_data = {
            "firstName": "Jane",
            "lastName": "Doe",
            "email": "jane.doe@example.com",
            "password": "password123",
            "phone": "1234567890"
        }
        user_response = self.app.post('/auth/register', data=json.dumps(user_data), content_type='application/json')

        # Get the userId from the database
        with app.app_context():
            user = User.query.filter_by(email=user_data['email']).first()
            user_id = user.userId

        # Add the user to the organisation
        response = self.app.post(f'/api/organisations/{org_id}/users', data=json.dumps({
            "userId": user_id
        }), headers={
            'x-access-tokens': token
        }, content_type='application/json')

        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
