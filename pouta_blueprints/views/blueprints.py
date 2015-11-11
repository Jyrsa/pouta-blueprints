from flask.ext.restful import marshal_with
from flask import abort, g
from flask import Blueprint as FlaskBlueprint

import logging

from pouta_blueprints.models import db, Blueprint, Plugin
from pouta_blueprints.forms import BlueprintForm
from pouta_blueprints.server import restful
from pouta_blueprints.views.commons import auth, blueprint_fields
from pouta_blueprints.utils import requires_admin
import re

blueprints = FlaskBlueprint('blueprints', __name__)

MAX_ACTIVATION_TOKENS_PER_USER = 3


@blueprints.route('/')
class BlueprintList(restful.Resource):
    @auth.login_required
    @marshal_with(blueprint_fields)
    def get(self):
        query = Blueprint.query
        if not g.user.is_admin:
            query = query.filter_by(is_enabled=True)

        results = []
        for blueprint in query.all():
            plugin = Plugin.query.filter_by(id=blueprint.plugin).first()
            blueprint.schema = plugin.schema
            blueprint.form = plugin.form
            results.append(blueprint)
        return results

    @auth.login_required
    @requires_admin
    def post(self):
        form = BlueprintForm()
        if not form.validate_on_submit():
            logging.warn("validation error on create blueprint")
            return form.errors, 422

        blueprint = Blueprint()
        blueprint.name = form.name.data
        blueprint.plugin = form.plugin.data
        blueprint.config = form.config.data

        if 'preallocated_credits' in form.config.data:
            try:
                blueprint.preallocated_credits = bool(form.config.data['preallocated_credits'])
            except:
                pass

        if 'maximum_lifetime' in form.config.data:

            timeformat_error = {"timeformat error": "pattern should be [days]d [hours]h [minutes]m"}
            try:
                max_life_str = str(form.config.data['maximum_lifetime'])
                if(max_life_str):
                    m = re.match(r'^(\d+d\s?)?(\d{1,2}h\s?)?(\d{1,2}m\s?)??$', max_life_str)

                    if(m):
                        days = hours = mins = 0
                        if(m.group(1)):
                            days = int(m.group(1).strip()[:-1])
                        if(m.group(2)):
                            hours = int(m.group(2).strip()[:-1])
                        if(m.group(3)):
                            mins = int(m.group(3).strip()[:-1])

                        blueprint.maximum_lifetime = days * 86400 + hours * 3600 + mins * 60

                    else:
                        return timeformat_error, 422
                else:
                    blueprint.maximum_lifetime = 3600  # Default value if not provided anything by user
            except:
                return timeformat_error, 422

        if 'cost_multiplier' in form.config.data:
            try:
                blueprint.cost_multiplier = float(form.config.data['cost_multiplier'])
            except:
                pass

        db.session.add(blueprint)
        db.session.commit()


@blueprints.route('/<string:blueprint_id>')
class BlueprintView(restful.Resource):
    @auth.login_required
    @marshal_with(blueprint_fields)
    def get(self, blueprint_id):
        return Blueprint.query.filter_by(id=blueprint_id).first()

    @auth.login_required
    @requires_admin
    def put(self, blueprint_id):
        form = BlueprintForm()
        if not form.validate_on_submit():
            logging.warn("validation error on update blueprint config")
            return form.errors, 422

        blueprint = Blueprint.query.filter_by(id=blueprint_id).first()
        if not blueprint:
            abort(404)
        blueprint.name = form.config.data.get('name') or form.name.data
        blueprint.config = form.config.data
        if 'preallocated_credits' in blueprint.config:
            try:
                blueprint.preallocated_credits = bool(blueprint.config['preallocated_credits'])
            except:
                pass

        if 'maximum_lifetime' in blueprint.config:

            timeformat_error = {"timeformat error": "pattern should be -d-h-m-s"}
            try:
                max_life_str = str(form.config.data['maximum_lifetime'])
                if(max_life_str):
                    m = re.match(r'^(\d+d\s?)?(\d{1,2}h\s?)?(\d{1,2}m\s?)?(\d{1,2}s\s?)?$', max_life_str)

                    if(m):
                        days = hours = mins = secs = 0
                        if(m.group(1)):
                            days = int(m.group(1).strip()[:-1])
                        if(m.group(2)):
                            hours = int(m.group(2).strip()[:-1])
                        if(m.group(3)):
                            mins = int(m.group(3).strip()[:-1])
                        if(m.group(4)):
                            secs = int(m.group(4).strip()[:-1])

                        blueprint.maximum_lifetime = days * 86400 + hours * 3600 + mins * 60 + secs
                    else:
                        return timeformat_error, 422
                else:
                    blueprint.maximum_lifetime = 3600  # Default value
            except:
                return timeformat_error, 422

        if 'cost_multiplier' in blueprint.config:
            try:
                blueprint.cost_multiplier = float(blueprint.config['cost_multiplier'])
            except:
                pass

        blueprint.plugin = form.plugin.data
        blueprint.is_enabled = form.is_enabled.data

        db.session.add(blueprint)
        db.session.commit()
