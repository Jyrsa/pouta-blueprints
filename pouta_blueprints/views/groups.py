# from flask.ext.restful import marshal_with
from flask import abort, g
from flask import Blueprint as FlaskBlueprint

import logging
import json
from pouta_blueprints.models import db, Group, User
from pouta_blueprints.forms import GroupForm
from pouta_blueprints.server import restful
from pouta_blueprints.views.commons import auth
from pouta_blueprints.utils import requires_admin, requires_group_owner_or_admin

groups = FlaskBlueprint('groups', __name__)


class GroupList(restful.Resource):
    @auth.login_required
    @requires_group_owner_or_admin
    def get(self):

        user = g.user
        if not user.is_admin:
            results = user.groups()
        else:
            query = Group.query
            results = []
            for group in query.all():
                results.add(group)
        return results

    @auth.login_required
    @requires_group_owner_or_admin
    def post(self):
        form = GroupForm()
        if not form.validate_on_submit():
            logging.warn("validation error on creating group")
            return form.errors, 422

        group = Group(form.name.data)
        group.description = form.description.data
        users_id_str = form.users.data
        if users_id_str:
            users_id = json.loads(form.users.data)
            for user_id in users_id:
                user = User.query.filter_by(id=user_id)
                if user:
                    group.users.append(user)


class GroupView(restful.Resource):
    @auth.login_required
    @requires_admin
    def get(self, group_id):

        query = Group.query.filter_by(id=group_id)
        group = query.first()
        if not group:
            abort(404)
        return group

    @auth.login_required
    @requires_group_owner_or_admin
    def put(self, group_id):
        form = GroupForm()
        if not form.validate_on_submit():
            logging.warn("validation error on creating group")
            return form.errors, 422

        user = g.user
        group = Group.query.filter_by(id=group_id).first()
        if not user.is_admin and group not in user.groups:
            abort(403)
        group.name = form.name.data
        group.description = form.description.data
        users_id_str = form.users.data
        if users_id_str:
            users_id = json.loads(form.users.data)
            for user_id in users_id:
                user = User.query.filter_by(id=user_id)
                if user:
                    group.users.append(user)

    @auth.login_required
    @requires_admin
    def delete(self, group_id):
        group = Group.query.filter_by(id=group_id).first()
        if not group:
            logging.warn("trying to delete non-existing group")
            abort(404)
        group.delete()
        db.session.commit()
