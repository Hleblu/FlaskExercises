#Lunchev IK-32
from flask import Flask, request
from flask_restful import Api, Resource
from marshmallow import Schema, fields
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "jose"
api = Api(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)

with app.app_context():
    db.create_all()

#db models
class UserModel(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class ItemModel(db.Model):
    __tablename__ = "items"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    price = db.Column(db.Float(precision=2), unique=False, nullable=False)

    store_id = db.Column(
        db.Integer, db.ForeignKey("stores.id"), unique=False, nullable=False
    )
    store = db.relationship("StoreModel", back_populates="items")

    tags = db.relationship("TagModel", back_populates="items", secondary="items_tags")

class StoreModel(db.Model):
    __tablename__ = "stores"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    items = db.relationship("ItemModel", back_populates="store", lazy="dynamic")
    tags = db.relationship("TagModel", back_populates="store", lazy="dynamic")


class TagModel(db.Model):
    __tablename__ = "tags"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=False, nullable=False)
    store_id = db.Column(db.Integer, db.ForeignKey("stores.id"), nullable=False)

    store = db.relationship("StoreModel", back_populates="tags")
    items = db.relationship("ItemModel", back_populates="tags", secondary="items_tags")

#schemes
class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True)
    password = fields.Str(required=True)

class PlainTagSchema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str()


class PlainItemSchema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str(required=True)
    price = fields.Float(required=True)


class PlainStoreSchema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str()


class ItemSchema(PlainItemSchema):
    store_id = fields.Int(required=True, load_only=True)
    store = fields.Nested(PlainStoreSchema(), dump_only=True)
    tags = fields.List(fields.Nested(PlainTagSchema()), dump_only=True)


class ItemUpdateSchema(Schema):
    name = fields.Str()
    price = fields.Float()


class StoreSchema(PlainStoreSchema):
    items = fields.List(fields.Nested(PlainItemSchema()), dump_only=True)
    tags = fields.List(fields.Nested(PlainTagSchema()), dump_only=True)


class TagSchema(PlainTagSchema):
    store_id = fields.Int(load_only=True)
    store = fields.Nested(PlainStoreSchema(), dump_only=True)


class TagAndItemSchema(Schema):
    message = fields.Str()
    item = fields.Nested(ItemSchema)
    tag = fields.Nested(TagSchema)

#association table
items_tags = db.Table(
    "items_tags",
    db.Column("id", db.Integer, primary_key=True),
    db.Column("item_id", db.Integer, db.ForeignKey("items.id")),
    db.Column("tag_id", db.Integer, db.ForeignKey("tags.id"))
)

#resources
class UserRegister(Resource):
    def post(self):
        data = request.get_json()
        user = UserModel(username=data["username"])
        user.set_password(data["password"])
        db.session.add(user)
        db.session.commit()
        return {"message": "User registered successfully"}, 200

class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        user = UserModel.query.filter_by(username=data["username"]).first()
        if user and user.check_password(data["password"]):
            access_token = create_access_token(identity=str(user.id))
            return {"access_token": access_token}, 200
        return {"message": "Invalid credentials"}, 401

class Item(Resource):
    @jwt_required()
    def get(self, name):
        item = ItemModel.query.filter_by(name=name).first() # повертає перший товар, чиє name збігається
        if item:
            return ItemSchema().dump(item)
        return {"message": "Item not found"}, 404

    @jwt_required()
    def post(self):
        data = request.get_json() # отримує дані з запиту
        item = ItemModel(**data)
        db.session.add(item) # додаємо
        db.session.commit() # зберігаємо
        return ItemSchema().dump(item)

    @jwt_required()
    def delete(self, name):
        item = ItemModel.query.filter_by(name=name).first()
        if item:
            db.session.delete(item)
            db.session.commit()
        return {"message": "Item deleted"}

class Store(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        store = StoreModel(**data)
        db.session.add(store)
        db.session.commit()
        return StoreSchema().dump(store)

    @jwt_required()
    def get(self, name):
        store = StoreModel.query.filter_by(name=name).first()
        if store:
            return StoreSchema().dump(store)
        return {"message": "Store not found"}, 404

class Tag(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        tag = TagModel(**data)
        db.session.add(tag)
        db.session.commit()
        return TagSchema().dump(tag)

    @jwt_required()
    def get(self, name):
        tag = TagModel.query.filter_by(name=name).first()
        if tag:
            return TagSchema().dump(tag)
        return {"message": "Tag not found"}, 404
    #delete tag completely
    @jwt_required()
    def delete(self, tag_id):
        tag = TagModel.query.get(tag_id)

        if len(tag.items) == 0:
            db.session.delete(tag)
            db.session.commit()
            return {"message": "Tag removed from item and deleted completely."}


class LinkTagToItem(Resource):
    @jwt_required()
    def post(self, item_id, tag_id):
        item = ItemModel.query.get(item_id)
        tag = TagModel.query.get(tag_id)

        if not item or not tag:
            return {"message": "Item or Tag not found"}, 404

        item.tags.append(tag)
        db.session.commit()

        return TagAndItemSchema().dump({"message": "Tag added to Item", "item": item, "tag": tag})

    # to unlink tag from item
    @jwt_required()
    def delete(self, item_id, tag_id):
        item = ItemModel.query.get(item_id)
        tag = TagModel.query.get(tag_id)

        if not item or not tag:
            return {"message": "Item or Tag not found"}, 404

        if tag in item.tags:
            item.tags.remove(tag)
            db.session.commit()

            return {"message": "Tag removed from item."}

        return {"message": "Tag not attached to item."}, 400

api.add_resource(UserRegister, "/register")
api.add_resource(UserLogin, "/login")
api.add_resource(Item, '/item/<string:name>', '/item')
api.add_resource(Store, "/store/<string:name>", "/store")
api.add_resource(Tag, "/tag/<string:name>", "/tag")
api.add_resource(LinkTagToItem, "/item/<int:item_id>/tag/<int:tag_id>")

if __name__ == "__main__":
    app.run(debug=True)