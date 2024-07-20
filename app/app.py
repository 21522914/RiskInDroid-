#!/usr/bin/env python3

import hashlib
import os
import subprocess
from subprocess import PIPE, run
import time

from flask import Flask, jsonify, make_response, render_template, request, send_from_directory, redirect, url_for
from model import Apk, db, Permission
from RiskInDroid import RiskInDroid
from sqlalchemy import cast
from sqlalchemy.sql import text
from werkzeug.exceptions import BadRequest, UnprocessableEntity
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"apk", "zip"}


def create_app():
    app = Flask(__name__)

    #trỏ đến đường dẫn tuyệt đối của các thư mục tương ứng trong thư mục chứa file Python đang chạy, ở đây là file app.py
    app.config["UPLOAD_DIR"] = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "upload"
    )
    app.config["APK_STORAGE_DIR"] = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "apk_files_from_phone"
    )
    app.config["MAX_CONTENT_LENGTH"] = 300 * 1024 * 1024

    app.config["DB_DIRECTORY"] = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "database"
    )
    app.config["DB_7Z_PATH"] = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "database", "permission_db.7z"
    )
    app.config["DB_PATH"] = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "database", "permission_db.db"
    )

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + app.config["DB_PATH"]
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Establish the database connection.
    db.init_app(app)

    # Create the upload directory (if not already existing).
    if not os.path.exists(app.config["UPLOAD_DIR"]):
        os.makedirs(app.config["UPLOAD_DIR"])
        
    # Create the copy file apks directory (if not already existing).
    if not os.path.exists(app.config["APK_STORAGE_DIR"]):
        os.makedirs(app.config["APK_STORAGE_DIR"])

    # Check if the database file is already extracted from the archive,
    # otherwise extract it.
    if not os.path.isfile(app.config["DB_PATH"]):
        instruction = '7z x "{0}" -o"{1}"'.format(
            app.config["DB_7Z_PATH"], app.config["DB_DIRECTORY"]
        )
        subprocess.run(instruction, shell=True)

    return app


application = create_app()


def check_if_valid_file_name(file_name):
    return (
        "." in file_name and file_name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )
    #.rslpit(sep, maxSplit) returns a list of the words in the string, using sep as the delimiter string. If maxsplit is given, at most maxsplit splits are done
    #ex: "hello.world.baby".rsplit(".", 1) returns ["hello.world", "baby"]


@application.after_request
def add_cache_header(response):
    response.headers[
        "Cache-Control"
    ] = "public, max-age=0, no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@application.errorhandler(400)
@application.errorhandler(422)
@application.errorhandler(500)
def application_error(error):
    return make_response(jsonify(str(error)), error.code)


@application.route("/", methods=["GET"], strict_slashes=False)
def home():
    return render_template("index.html")


@application.route("/results", methods=["GET"], strict_slashes=False)
def results():
    return render_template("results.html")


def get_installed_packages():
    results = subprocess.run(['adb', 'shell', 'pm', 'list', 'packages'] , capture_output=True, text=True)
    if results.returncode != 0:
        print("Error getting installed packages:", results.stderr)
        return []
    packages = results.stdout.splitlines()
    packages = [package.split(":")[1] for package in packages if ':' in package]
    return packages

def get_apk_path(package_name):
    # Get the path to the APK file for the specified package
    result = subprocess.run(["adb", "shell", "pm", "path", package_name], capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout:
        print(f"Error getting APK path for {package_name}: {result.stderr}")
        return None
    apk_path = result.stdout.split(":")[1].split("\n")[0].strip()
    return apk_path

def pull_apk(package_name):
    # Get the APK path on the device
    apk_path = get_apk_path(package_name)
    if not apk_path:
        return False
    # sử dụng adb pull để copy file 
    output_dir = os.path.join(application.config["APK_STORAGE_DIR"], f"{package_name}.apk")
    result = subprocess.run(['adb', 'pull', apk_path, output_dir], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print(f"Error pulling APK for {package_name}: {result.stderr}")
        return False
    return True

@application.route("/runadb", methods=["GET"], strict_slashes=False)
def runadb():
    #copy file apk từ điện thoại vào folder trong project
    packages = get_installed_packages()
    packages = get_installed_packages()
    pulled_packages = []
    failed_packages = []
    for package_name in packages:
        if pull_apk(package_name):
            pulled_packages.append(package_name)
        else:
            failed_packages.append(package_name)
    return render_template("results-phone-scan.html", packages_and_apks=pulled_packages, failed_packages=failed_packages)

@application.route('/go_back_homepage', methods=["GET"], strict_slashes=False)
def  go_back_homepage():
    folder_path = os.path.join(application.config["APK_STORAGE_DIR"])
    try:
        # Sử dụng lệnh `open` của macOS để mở thư mục bằng Finder
        subprocess.Popen(['open', folder_path])
        #subprocess.call(["open", folder_path])
        return redirect(url_for('home'))
    except Exception as e:
        return str(e)


@application.route("/upload", methods=["POST"], strict_slashes=False)
def upload_apk():
    # The POST request must contain a valid file.
    if "file" not in request.files:
        raise BadRequest("No file uploaded")
    file = request.files["file"] #access the file sent in http request
    if not file.filename.strip():   #delete white spaces in begin and end of the file name
        raise BadRequest("No file uploaded")

    if file and check_if_valid_file_name(file.filename):
        filename = secure_filename(file.filename) #làm sạch file name, đảm bảo không chứa các ký tự k an toàn

        file_path = os.path.join(
            application.config["UPLOAD_DIR"],
            "{0}_{1}".format(time.strftime("%H-%M-%S_%d-%m-%Y"), filename),
        )
        file.save(file_path)

        rid = RiskInDroid()

        permissions = rid.get_permission_json(file_path)

        try:
            response = {
                "name": filename,
                "md5": md5sum(file_path),
                "risk": round(
                    rid.calculate_risk(rid.get_feature_vector_from_json(permissions)),
                    3,
                ),
                "permissions": [
                    val
                    for val in list(
                        map(
                            lambda x: {"cat": "Declared", "name": x},
                            permissions["declared"],
                        )
                    )
                    + list(
                        map(
                            lambda x: {"cat": "Required and Used", "name": x},
                            permissions["requiredAndUsed"],
                        )
                    )
                    + list(
                        map(
                            lambda x: {"cat": "Required but Not Used", "name": x},
                            permissions["requiredButNotUsed"],
                        )
                    )
                    + list(
                        map(
                            lambda x: {"cat": "Not Required but Used", "name": x},
                            permissions["notRequiredButUsed"],
                        )
                    )
                ],
            }
            return make_response(jsonify(response))
        except Exception:
            raise BadRequest("The uploaded file is not valid")
    else:
        raise UnprocessableEntity("The uploaded file is not valid")


@application.route("/apks", methods=["GET"], strict_slashes=False)
def get_apks():
    query = Apk.query

    if request.args.get("sort") and request.args.get("sort_dir"):
        query = query.order_by(
            text(
                "{0} {1}".format(request.args.get("sort"), request.args.get("sort_dir"))
            )
        )

    if request.args.get("namefil"):
        fil = request.args.get("namefil").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(Apk.name.ilike("%{0}%".format(fil), "\\"))

    if request.args.get("md5fil"):
        fil = request.args.get("md5fil").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(Apk.md5.ilike("%{0}%".format(fil), "\\"))

    if request.args.get("riskfil"):
        fil = request.args.get("riskfil").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(cast(Apk.risk, db.String).ilike("%{0}%".format(fil), "\\"))

    pag = query.paginate()

    item_list = []

    for item in pag.items:
        item_list.append({"name": item.name, "md5": item.md5, "risk": item.risk})

    response = {"current_page": pag.page, "last_page": pag.pages, "data": item_list}

    return make_response(jsonify(response))


@application.route("/details", methods=["GET", "POST"], strict_slashes=False)
def get_apk_details():
    if request.method == "GET":
        try:
            # An exception will be thrown if the query string doesn't contain an md5.
            md5 = request.args["md5"]
            apk = Apk.query.get(md5)
            response = {
                "name": apk.name,
                "md5": apk.md5,
                "risk": apk.risk,
                "type": apk.type,
                "source": apk.source,
                "permissions": [
                    val
                    for val in list(
                        map(
                            lambda x: {"cat": "Declared", "name": x.name},
                            apk.declared_permissions,
                        )
                    )
                    + list(
                        map(
                            lambda x: {"cat": "Required and Used", "name": x.name},
                            apk.required_and_used_permissions,
                        )
                    )
                    + list(
                        map(
                            lambda x: {"cat": "Required but Not Used", "name": x.name},
                            apk.required_but_not_used_permissions,
                        )
                    )
                    + list(
                        map(
                            lambda x: {"cat": "Not Required but Used", "name": x.name},
                            apk.not_required_but_used_permissions,
                        )
                    )
                ],
            }
            return make_response(jsonify(response))
        except Exception:
            raise BadRequest("Unable to get details for the specified application")

    if request.method == "POST":
        response = {
            "name": request.form["name"],
            "md5": request.form["md5"],
            "risk": request.form["risk"],
            "permissions": request.form["permissions"],
        }
        return render_template("details.html", apk=response)


def md5sum(file_path, block_size=65536):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as filename:
        for chunk in iter(lambda: filename.read(block_size), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()



if __name__ == "__main__":
    application.run(host="0.0.0.0", port=4500, debug=True)
