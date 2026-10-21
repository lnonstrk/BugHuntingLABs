"""
ShopNest IDOR lab - INTENTIONALLY VULNERABLE. LOCAL USE ONLY.
Run: python app.py   then open http://127.0.0.1:5000
Every API call is a real HTTP request, so Burp Suite can capture and modify it.
Set Burp as the browser proxy (127.0.0.1:8080) and make sure 127.0.0.1 is not bypassed.
"""
import copy
import os

from flask import Flask, Response, jsonify, request, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

SEED = {
    "users": {
        1: {"name": "Alice Sharma", "email": "alice@shopnest.test", "password": "alice123", "role": "user",
            "phone": "+91 90000 00001", "address": "Flat 1, Linking Road, Mumbai"},
        2: {"name": "Bob Verma", "email": "bob@shopnest.test", "password": "bob123", "role": "user",
            "phone": "+91 90000 00002", "address": "12 MG Road, Pune"},
        3: {"name": "Priya Nair", "email": "admin@shopnest.test", "password": "admin123", "role": "admin",
            "phone": "+91 90000 00003", "address": "ShopNest HQ, Bengaluru"},
    },
    "orders": {
        500: {"owner_id": 1, "item": "Laptop Bag", "amount": 1200, "status": "Shipped", "date": "2026-10-02"},
        501: {"owner_id": 2, "item": "Wireless Mouse", "amount": 2500, "status": "Pending", "date": "2026-10-15"},
        502: {"owner_id": 1, "item": "USB-C Cable", "amount": 300, "status": "Delivered", "date": "2026-09-28"},
        503: {"owner_id": 3, "item": "Office Chair", "amount": 9000, "status": "Processing", "date": "2026-10-18"},
    },
    "invoices": {
        101: {"owner_id": 1, "total": 1200, "date": "2026-10-02"},
        102: {"owner_id": 2, "total": 2500, "date": "2026-10-15"},
    },
    "files": {
        "invoice_500.txt": {"owner_id": 1, "body": "ShopNest Invoice #500\nCustomer: Alice Sharma\nItem: Laptop Bag\nAmount: Rs 1200"},
        "invoice_501.txt": {"owner_id": 2, "body": "ShopNest Invoice #501\nCustomer: Bob Verma\nItem: Wireless Mouse\nAmount: Rs 2500"},
    },
    "reviews": {
        1: {"owner_id": 1, "product": "Laptop Bag", "rating": 5, "text": "Bag mast hai, quality achhi."},
        2: {"owner_id": 2, "product": "Wireless Mouse", "rating": 4, "text": "Delivery fast thi."},
    },
}

DB = copy.deepcopy(SEED)


def toint(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def current():
    """Identity comes from the user_id cookie. The client controls it."""
    uid = toint(request.cookies.get("user_id"))
    return uid, DB["users"].get(uid)


def unauth():
    return jsonify(error="Login required"), 401


@app.route("/")
def index():
    return send_from_directory(BASE, "index.html")


@app.route("/api/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or {}
    for uid, u in DB["users"].items():
        if u["email"] == d.get("email") and u["password"] == d.get("password"):
            return jsonify(user_id=uid)
    return jsonify(error="Email ya password galat hai"), 401


@app.route("/api/me")
def api_me():
    uid, user = current()
    if not user:
        return unauth()
    return jsonify(user_id=uid, **user)


# ---------- Orders ----------
@app.route("/api/my-orders")
def my_orders():
    uid, user = current()
    if not user:
        return unauth()
    return jsonify(orders=[{"oid": k, **o} for k, o in DB["orders"].items() if o["owner_id"] == uid])


# Mobile API: no ownership check (horizontal IDOR)
@app.route("/api/orders/<int:oid>")
def api_order(oid):
    uid, user = current()
    if not user:
        return unauth()
    o = DB["orders"].get(oid)
    if not o:
        return jsonify(error="not found"), 404
    return jsonify(oid=oid, **o)


# Web route: ownership check exists, but the 403 body leaks the other user's data
@app.route("/orders/<int:oid>")
def web_order(oid):
    uid, user = current()
    if not user:
        return unauth()
    o = DB["orders"].get(oid)
    if not o:
        return jsonify(error="not found"), 404
    if o["owner_id"] != uid:
        owner = DB["users"].get(o["owner_id"], {}).get("name", "kisi aur")
        return jsonify(error="Access denied",
                       detail=f"Ye order {owner} ka hai: {o['item']}, Rs {o['amount']}"), 403
    return jsonify(oid=oid, **o)


# Method-based IDOR: DELETE has no check
@app.route("/orders/<int:oid>", methods=["DELETE"])
def delete_order(oid):
    uid, user = current()
    if not user:
        return unauth()
    if oid not in DB["orders"]:
        return jsonify(error="not found"), 404
    del DB["orders"][oid]
    return jsonify(deleted=oid)


# HTTP Parameter Pollution: check first id, fetch last id
@app.route("/order")
def track_order():
    uid, user = current()
    if not user:
        return unauth()
    ids = request.args.getlist("id")
    if not ids:
        return jsonify(error="id required"), 400
    first = DB["orders"].get(toint(ids[0]))
    if not first or first["owner_id"] != uid:
        return jsonify(error="Access denied"), 403
    last = ids[-1]
    o = DB["orders"].get(toint(last))
    if not o:
        return jsonify(error="not found"), 404
    return jsonify(id=toint(last), **o)


# Body IDOR (write)
@app.route("/api/orders/update", methods=["POST"])
def update_order():
    uid, user = current()
    if not user:
        return unauth()
    d = request.get_json(silent=True) or {}
    o = DB["orders"].get(toint(d.get("order_id")))
    if not o:
        return jsonify(error="not found"), 404
    o["status"] = d.get("status") or o["status"]
    return jsonify(updated=d.get("order_id"), order=dict(o))


# ---------- Invoices and files ----------
@app.route("/api/my-invoices")
def my_invoices():
    uid, user = current()
    if not user:
        return unauth()
    return jsonify(invoices=[{"invoice_id": k, **i} for k, i in DB["invoices"].items() if i["owner_id"] == uid])


# Query IDOR: no owner check
@app.route("/invoice")
def invoice():
    uid, user = current()
    if not user:
        return unauth()
    iid = toint(request.args.get("invoice_id"))
    inv = DB["invoices"].get(iid)
    if not inv:
        return jsonify(error="not found"), 404
    return jsonify(invoice_id=iid, **inv)


# File IDOR: no owner check
@app.route("/download")
def download():
    uid, user = current()
    if not user:
        return unauth()
    f = DB["files"].get(request.args.get("file", ""))
    if not f:
        return jsonify(error="not found"), 404
    return Response(f["body"], mimetype="text/plain")


# ---------- Profiles ----------
# Query IDOR with PII
@app.route("/profile")
def profile():
    uid, user = current()
    if not user:
        return unauth()
    pid = toint(request.args.get("user_id"))
    other = DB["users"].get(pid)
    if not other:
        return jsonify(error="not found"), 404
    return jsonify(user_id=pid, name=other["name"], email=other["email"],
                   phone=other["phone"], address=other["address"])


# Header IDOR: identity taken from X-User-Id
@app.route("/api/my-profile")
def my_profile():
    uid, user = current()
    if not user:
        return unauth()
    hid = request.headers.get("X-User-Id")
    target = toint(hid) if hid else uid
    t = DB["users"].get(target)
    if not t:
        return jsonify(error="not found"), 404
    return jsonify(user_id=target, **t)


# Mass assignment: self check exists, but role is accepted from the request
@app.route("/api/users/<int:target_id>", methods=["PUT"])
def update_user(target_id):
    uid, user = current()
    if not user:
        return unauth()
    if target_id != uid:
        return jsonify(error="Access denied"), 403
    d = request.get_json(silent=True) or {}
    for k, v in d.items():
        DB["users"][target_id][k] = v
    return jsonify(user_id=target_id, **DB["users"][target_id])


# ---------- Reviews ----------
@app.route("/api/my-review")
def my_review():
    uid, user = current()
    if not user:
        return unauth()
    for rid, r in DB["reviews"].items():
        if r["owner_id"] == uid:
            return jsonify(review_id=rid, **r)
    return jsonify(error="No review"), 404


# IDOR on write: no owner check
@app.route("/api/reviews/<int:rid>", methods=["PUT"])
def update_review(rid):
    uid, user = current()
    if not user:
        return unauth()
    r = DB["reviews"].get(rid)
    if not r:
        return jsonify(error="not found"), 404
    d = request.get_json(silent=True) or {}
    if d.get("text"):
        r["text"] = d["text"]
    return jsonify(review_id=rid, **r)


# ---------- Admin ----------
@app.route("/api/admin/users")
def admin_users():
    uid, user = current()
    if not user:
        return unauth()
    if user["role"] != "admin":
        return jsonify(error="Admin access required"), 403
    return jsonify(users=[{"user_id": k, "name": v["name"], "email": v["email"], "role": v["role"]}
                          for k, v in DB["users"].items()])


# Missing function-level access control: no role check
@app.route("/admin/delete-user/<int:target_id>")
def admin_delete_user(target_id):
    uid, user = current()
    if not user:
        return unauth()
    t = DB["users"].get(target_id)
    if not t:
        return jsonify(error="not found"), 404
    name = t["name"]
    del DB["users"][target_id]
    return jsonify(deleted=name)


# Correct reference route
@app.route("/secure/orders/<int:oid>")
def secure_order(oid):
    uid, user = current()
    if not user:
        return unauth()
    o = DB["orders"].get(oid)
    if not o or (o["owner_id"] != uid and user["role"] != "admin"):
        return jsonify(error="not found"), 404
    return jsonify(oid=oid, **o)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
