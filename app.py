"""College Shield Flask API.

Vercel entry point: app

Required production environment variables:
    MONGODB_URI
    DB_NAME
    CLERK_JWKS_URL
    CLERK_ISSUER
    FRONTEND_ORIGINS

Browser requests must include:
    Authorization: Bearer <Clerk session token>
"""

from __future__ import annotations

import logging
import os
import re
import threading
from datetime import date, datetime, timezone
from functools import wraps
from typing import Any, Callable

import jwt
from bson import ObjectId
from flask import Flask, g, jsonify, request
from flask_cors import CORS
from jwt import PyJWKClient
from pymongo.collection import Collection


# ============================================================
# FLASK CONFIGURATION
# ============================================================

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024
app.config["JSON_SORT_KEYS"] = False

_allowed_origins = [
    item.strip().rstrip("/")
    for item in os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:5173"
    ).split(",")
    if item.strip()
]

CORS(
    app,
    origins=_allowed_origins,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    supports_credentials=False,
    max_age=86400,
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO")
)

logger = app.logger


# ============================================================
# LAZY DATABASE INITIALIZATION
# ============================================================

visits_collection: Collection | None = None
receipts_collection: Collection | None = None
users_collection: Collection | None = None
roles_collection: Collection | None = None
students_collection: Collection | None = None

_db_initialized = False
_db_init_lock = threading.Lock()


def seed_roles() -> None:
    """Create default roles without overwriting existing settings."""

    default_roles = [
        {
            "name": "admin",
            "page_permissions": [
                "/admin",
                "/guard",
                "/apply",
                "/receipts",
                "/dashboard",
            ],
            "field_permissions": ["all"],
        },
        {
            "name": "sub_admin",
            "page_permissions": [
                "/guard",
                "/apply",
                "/receipts",
                "/dashboard",
            ],
            "field_permissions": [
                "read_visits",
                "update_status",
            ],
        },
        {
            "name": "member",
            "page_permissions": [
                "/apply",
                "/receipts",
                "/dashboard",
            ],
            "field_permissions": [
                "create_visit",
                "read_own_receipts",
            ],
        },
    ]

    for role in default_roles:
        roles_collection.update_one(
            {"name": role["name"]},
            {"$setOnInsert": role},
            upsert=True,
        )


def initialize_database() -> None:
    """Initialize MongoDB collections once per warm worker."""

    global _db_initialized
    global visits_collection
    global receipts_collection
    global users_collection
    global roles_collection
    global students_collection

    if _db_initialized:
        return

    with _db_init_lock:

        if _db_initialized:
            return

        from models import (
            ensure_indexes,
            receipts_collection as receipts,
            roles_collection as roles,
            students_collection as students,
            users_collection as users,
            visits_collection as visits,
        )

        visits_collection = visits
        receipts_collection = receipts
        users_collection = users
        roles_collection = roles
        students_collection = students

        seed_roles()
        ensure_indexes()

        _db_initialized = True


# ============================================================
# CLERK AUTHENTICATION
# ============================================================

_jwks_client: PyJWKClient | None = None
_jwks_url_cached: str | None = None
_jwks_lock = threading.Lock()


def get_jwks_client() -> PyJWKClient:
    """Return cached Clerk JWKS client."""

    global _jwks_client
    global _jwks_url_cached

    jwks_url = os.getenv("CLERK_JWKS_URL", "").strip()

    if not jwks_url:
        raise RuntimeError(
            "CLERK_JWKS_URL is not configured"
        )

    with _jwks_lock:

        if (
            _jwks_client is None
            or _jwks_url_cached != jwks_url
        ):
            _jwks_client = PyJWKClient(jwks_url)
            _jwks_url_cached = jwks_url

    return _jwks_client


def verify_clerk_session_token(token: str) -> dict[str, Any]:
    """Verify Clerk JWT signature, algorithm, issuer and expiry."""

    issuer = os.getenv("CLERK_ISSUER", "").strip()

    if not issuer:
        raise RuntimeError(
            "CLERK_ISSUER is not configured"
        )

    signing_key = (
        get_jwks_client()
        .get_signing_key_from_jwt(token)
    )

    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        issuer=issuer,
        options={"verify_aud": False},
        leeway=10,
    )

    clerk_user_id = claims.get("sub")

    if (
        not isinstance(clerk_user_id, str)
        or not clerk_user_id.startswith("user_")
    ):
        raise jwt.InvalidTokenError(
            "Token does not identify a Clerk user"
        )

    authorized_party = claims.get("azp")

    if (
        authorized_party
        and _allowed_origins
        and authorized_party.rstrip("/") not in _allowed_origins
    ):
        raise jwt.InvalidTokenError(
            "Unauthorized frontend origin"
        )

    return claims


def require_authentication():

    auth_header = request.headers.get(
        "Authorization", ""
    )

    scheme, _, token = auth_header.partition(" ")

    if scheme.lower() != "bearer" or not token.strip():
        return (
            None,
            (
                jsonify({
                    "error": "Authentication required"
                }),
                401,
            ),
        )

    try:

        claims = verify_clerk_session_token(
            token.strip()
        )

        return claims, None

    except RuntimeError as exc:

        logger.error(
            "Clerk configuration error: %s",
            exc
        )

        return (
            None,
            (
                jsonify({
                    "error": "Authentication service is not configured"
                }),
                503,
            ),
        )

    except Exception as exc:

        logger.warning(
            "Clerk verification failed: %s",
            type(exc).__name__
        )

        return (
            None,
            (
                jsonify({
                    "error": "Invalid or expired session"
                }),
                401,
            ),
        )


@app.before_request
def prepare_api_request():

    if (
        request.path in ("/", "/healthz")
        or request.method == "OPTIONS"
    ):
        return None

    if not request.path.startswith("/api/"):
        return None

    claims, auth_error = require_authentication()

    if auth_error:
        return auth_error

    g.clerk_user_id = claims["sub"]
    g.clerk_claims = claims

    try:
        initialize_database()

    except Exception:

        logger.exception(
            "Database initialization failed"
        )

        return (
            jsonify({
                "error": "Database is not ready"
            }),
            503,
        )

    return None


# ============================================================
# ROLE-BASED ACCESS CONTROL
# ============================================================

def require_roles(*allowed_roles: str) -> Callable:

    def decorator(view_function: Callable):

        @wraps(view_function)
        def wrapped(*args, **kwargs):

            user = users_collection.find_one(
                {
                    "clerk_id": g.clerk_user_id
                },
                {
                    "role_name": 1
                },
            )

            role_name = (
                user.get("role_name", "member")
                if user
                else "member"
            )

            if role_name not in allowed_roles:

                return (
                    jsonify({
                        "error": "Insufficient permissions"
                    }),
                    403,
                )

            g.current_role = role_name

            return view_function(*args, **kwargs)

        return wrapped

    return decorator


def current_user_role() -> str:

    user = users_collection.find_one(
        {
            "clerk_id": g.clerk_user_id
        },
        {
            "role_name": 1
        },
    )

    return (
        user.get("role_name", "member")
        if user
        else "member"
    )


# ============================================================
# COMMON HELPERS
# ============================================================

@app.errorhandler(413)
def request_too_large(_error):

    return (
        jsonify({
            "error": (
                "Request body is too large. "
                "Resize the image and try again."
            )
        }),
        413,
    )


def get_json_object():

    data = request.get_json(silent=True)

    return (
        data
        if isinstance(data, dict)
        else None
    )


def serialize_doc(doc):

    if doc is None:
        return None

    result = dict(doc)

    if "_id" in result:
        result["_id"] = str(result["_id"])

    return result


def parse_object_id(value):

    try:
        return ObjectId(value)

    except Exception:
        return None


def member_owned_filter():

    return {
        "createdByClerkId": g.clerk_user_id
    }


# ============================================================
# VALIDATION FUNCTIONS
# ============================================================

def sanitize_indian_plate(raw_text):

    if not isinstance(raw_text, str) or not raw_text:
        return ""

    clean_text = re.sub(
        r"[^A-Z0-9]",
        "",
        raw_text.upper()
    )

    state_codes = (
        r"(AP|AR|AS|BR|CG|GA|GJ|HR|HP|JH|KA|KL|MP|MH|"
        r"MN|ML|MZ|NL|OD|PB|RJ|SK|TN|TS|TR|UP|UK|WB|"
        r"AN|CH|DN|DD|DL|JK|LA|LD|PY|BH)"
    )

    match = re.search(
        rf"({state_codes}[A-Z0-9]{{7,8}})",
        clean_text
    )

    if match:
        return match.group(1)

    clean_text = re.sub(
        r"^(IND|1ND|IN0|INO|JND|ND|IN)",
        "",
        clean_text
    )

    fallback_match = re.search(
        r"([A-Z]{2}[A-Z0-9]{7,8})",
        clean_text
    )

    if fallback_match:
        return fallback_match.group(1)

    if 9 <= len(clean_text) <= 10:
        return clean_text

    return (
        clean_text[-10:]
        if len(clean_text) > 10
        else clean_text
    )


def build_db_fuzzy_regex(db_plate):

    if not isinstance(db_plate, str) or not db_plate:
        return ""

    confusion_map = {
        "0": "[0ODQ]",
        "O": "[0ODQ]",
        "D": "[0ODQ]",
        "Q": "[0ODQ]",
        "1": "[1ILT]",
        "I": "[1ILT]",
        "L": "[1ILT]",
        "T": "[1ILT]",
        "8": "[8B]",
        "B": "[8B]",
        "5": "[5S]",
        "S": "[5S]",
        "2": "[2Z]",
        "Z": "[2Z]",
        "A": "[A4H]",
        "4": "[A4HL]",
        "H": "[A4H]",
        "G": "[G6C]",
        "6": "[G6C]",
        "C": "[CGO0]",
        "V": "[VUY]",
        "U": "[VUY]",
        "Y": "[VUY]",
    }

    clean_db_plate = re.sub(
        r"[^A-Z0-9]",
        "",
        db_plate.upper()
    )

    import re as regex_module

    return "".join(
        confusion_map.get(
            char,
            regex_module.escape(char)
        ) + r".?"
        for char in clean_db_plate
    )


def is_valid_name(name):

    if not isinstance(name, str):
        return False

    return bool(
        re.fullmatch(
            r"[A-Za-z]{2,}(?: [A-Za-z]+)*",
            name.strip()
        )
    )


def validate_student_id_format(student_id):

    return (
        isinstance(student_id, str)
        and bool(
            re.fullmatch(
                r"[A-Z]{5}\d{5}",
                student_id.strip()
            )
        )
    )


def validate_names_in_payload(data):

    name_fields = [
        "name",
        "hostName",
        "studentName",
        "fatherName",
        "motherName",
        "guardianName",
    ]

    for field in name_fields:

        value = data.get(field)

        if value and not is_valid_name(value):

            return (
                False,
                (
                    "Invalid input: Name must contain "
                    f"only alphabets and spaces ({field})"
                ),
            )

    for collection_field in (
        "members",
        "authorizedPersons",
    ):

        entries = data.get(
            collection_field,
            []
        )

        if entries is not None:

            if not isinstance(entries, list):

                return (
                    False,
                    f"{collection_field} must be a list"
                )

            for entry in entries:

                if not isinstance(entry, dict):

                    return (
                        False,
                        f"Each item in {collection_field} must be an object"
                    )

                value = entry.get("name")

                if value and not is_valid_name(value):

                    return (
                        False,
                        "Invalid input: Name must contain only alphabets and spaces"
                    )

    return True, ""


def validate_contacts_in_payload(data):

    email_pattern = (
        r"[A-Za-z0-9._%+-]+"
        r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    )

    email = data.get("email")

    if email and not re.fullmatch(
        email_pattern,
        str(email).strip()
    ):

        return False, "Invalid email format"

    mobile_no = data.get("mobileNo")

    if mobile_no and not re.fullmatch(
        r"\d{10}",
        str(mobile_no).strip()
    ):

        return (
            False,
            "Phone number must be exactly 10 digits"
        )

    authorized_persons = data.get(
        "authorizedPersons",
        []
    )

    if authorized_persons is not None:

        if not isinstance(authorized_persons, list):

            return False, "authorizedPersons must be a list"

        for person in authorized_persons:

            if not isinstance(person, dict):

                return (
                    False,
                    "Each authorized person must be an object"
                )

            mobile = person.get("mobile")

            if mobile and not re.fullmatch(
                r"\d{10}",
                str(mobile).strip()
            ):

                return (
                    False,
                    "Phone number must be exactly 10 digits"
                )

    return True, ""


def validate_student_registration_data(data):

    student_id = data.get("studentId")

    if not validate_student_id_format(student_id):

        return (
            False,
            (
                "Student ID must be exactly 5 uppercase "
                "letters followed by 5 numbers "
                "(e.g., ABCDE12345)."
            ),
        )

    income = data.get("guardianIncome")

    if income is None or str(income).strip() == "":

        return False, "Annual income is required."

    income_text = str(income).strip()

    if not income_text.isdigit():

        return (
            False,
            "Income must contain only numbers "
            "(no text or symbols allowed)."
        )

    income_value = int(income_text)

    if income_value > 1_000_000_000:

        return False, "Income exceeds realistic limits."

    dob_value = data.get("dob")

    if not isinstance(dob_value, str) or not dob_value:

        return False, "Date of Birth is required."

    try:

        dob_date = datetime.strptime(
            dob_value[:10],
            "%Y-%m-%d"
        ).date()

        today = date.today()

        try:

            minimum_birth_date = today.replace(
                year=today.year - 11
            )

        except ValueError:

            minimum_birth_date = today.replace(
                year=today.year - 11,
                day=28
            )

        if dob_date > minimum_birth_date:

            return (
                False,
                "Applicant must be at least 11 years old."
            )

    except ValueError:

        return False, "Invalid Date of Birth format."

    return True, ""


# ============================================================
# RECEIPT STATUS SYNCHRONIZATION
# ============================================================

def auto_sync_receipt_status(
    visitor_id_obj,
    visit_doc,
    new_status
):

    try:

        query = {
            "$or": [
                {
                    "visitorId": str(visitor_id_obj)
                },
                {
                    "visitId": str(visitor_id_obj)
                },
            ]
        }

        if visit_doc and "submittedAt" in visit_doc:

            query["$or"].append(
                {
                    "submittedAt": visit_doc["submittedAt"],
                    "name": visit_doc.get("name"),
                }
            )

        receipts_collection.update_many(
            query,
            {
                "$set": {
                    "status": new_status
                }
            }
        )

    except Exception:

        logger.exception(
            "Failed to synchronize receipt status"
        )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
@app.route("/healthz", methods=["GET"])
def health_check():

    return jsonify({
        "status": "ok",
        "service": "college-shield-api"
    }), 200


# ============================================================
# AUTHENTICATION AND PERMISSIONS
# ============================================================

@app.route("/api/auth/sync", methods=["POST"])
def sync_user():

    data = get_json_object() or {}

    supplied_clerk_id = data.get("clerk_id")

    if (
        supplied_clerk_id
        and supplied_clerk_id != g.clerk_user_id
    ):

        return (
            jsonify({
                "error": "Clerk user ID does not match the authenticated session"
            }),
            403,
        )

    email = data.get("email")

    if email is not None and not isinstance(email, str):

        return (
            jsonify({
                "error": "Email must be a string"
            }),
            400,
        )

    existing_user = users_collection.find_one(
        {
            "clerk_id": g.clerk_user_id
        }
    )

    # Never accept role changes from the browser.
    final_role = (
        existing_user.get("role_name")
        if existing_user and existing_user.get("role_name")
        else "member"
    )

    update_fields = {
        "role_name": final_role,
        "updatedAt": datetime.now(timezone.utc),
    }

    if email:

        update_fields["email"] = email.strip().lower()

    users_collection.update_one(
        {
            "clerk_id": g.clerk_user_id
        },
        {
            "$set": update_fields,
            "$setOnInsert": {
                "createdAt": datetime.now(timezone.utc)
            },
        },
        upsert=True,
    )

    return jsonify({
        "message": "User synced",
        "role": final_role
    }), 200


@app.route("/api/auth/permissions", methods=["GET"])
def get_permissions():

    requested_clerk_id = request.args.get(
        "clerk_id"
    )

    if (
        requested_clerk_id
        and requested_clerk_id != g.clerk_user_id
    ):

        return (
            jsonify({
                "error": "Cannot read another user's permissions"
            }),
            403,
        )

    user = users_collection.find_one(
        {
            "clerk_id": g.clerk_user_id
        }
    )

    if not user:

        return jsonify({
            "role": "unassigned",
            "page_permissions": [],
            "field_permissions": [],
        }), 200

    role_data = roles_collection.find_one(
        {
            "name": user.get("role_name", "member")
        }
    )

    if not role_data:

        return (
            jsonify({
                "error": "Role configuration missing"
            }),
            404,
        )

    return jsonify({
        "role": role_data.get("name"),
        "page_permissions": role_data.get(
            "page_permissions",
            []
        ),
        "field_permissions": role_data.get(
            "field_permissions",
            []
        ),
    }), 200


# ============================================================
# VISITOR PASSES
# ============================================================

@app.route(
    "/api/visits",
    methods=["POST", "GET"]
)
def handle_visits():

    if request.method == "GET":

        role_name = current_user_role()

        query = (
            {}
            if role_name in ("admin", "sub_admin")
            else member_owned_filter()
        )

        visits = (
            visits_collection
            .find(query)
            .sort("_id", -1)
            .limit(50)
        )

        return jsonify([
            serialize_doc(visit)
            for visit in visits
        ]), 200

    data = get_json_object()

    if not data:

        return (
            jsonify({
                "error": "No JSON object provided"
            }),
            400,
        )

    valid_names, message = validate_names_in_payload(
        data
    )

    if not valid_names:

        return jsonify({
            "error": message
        }), 400

    visitor_type = data.get("visitorType")

    if (
        visitor_type == "student"
        and not validate_student_id_format(
            data.get("studentId")
        )
    ):

        return (
            jsonify({
                "error": (
                    "Student ID must be exactly 5 uppercase "
                    "letters followed by 5 numbers "
                    "(e.g., ABCDE12345)."
                )
            }),
            400,
        )

    if (
        visitor_type == "parent"
        and not validate_student_id_format(
            data.get("hostId")
        )
    ):

        return (
            jsonify({
                "error": (
                    "Host Student ID must be exactly "
                    "5 uppercase letters followed "
                    "by 5 numbers (e.g., ABCDE12345)."
                )
            }),
            400,
        )

    image_b64 = data.get("vehicleNoPhoto")

    if image_b64:

        if not isinstance(image_b64, str):

            return (
                jsonify({
                    "error": "vehicleNoPhoto must be a base64 image string"
                }),
                400,
            )

        try:

            from plate_ocr import extract_plate_from_base64

            data["vehiclePlateDetails"] = {
                "text": sanitize_indian_plate(
                    extract_plate_from_base64(image_b64)
                )
            }

        except Exception:

            logger.exception(
                "Vehicle plate OCR failed during visit submission"
            )

            return (
                jsonify({
                    "error": "Vehicle number recognition failed"
                }),
                500,
            )

    # Ownership comes from the verified session, not request JSON.
    data.pop("createdByClerkId", None)

    data["createdByClerkId"] = g.clerk_user_id

    data["status"] = (
        data.get("status")
        or "pending_review"
    )

    data["submittedAt"] = datetime.now(timezone.utc)

    try:

        result = visits_collection.insert_one(data)

        receipt_data = dict(data)

        receipt_data["visitorId"] = str(
            result.inserted_id
        )

        receipts_collection.insert_one(
            receipt_data
        )

        return jsonify({
            "message": "Success",
            "id": str(result.inserted_id),
        }), 201

    except Exception:

        logger.exception(
            "Failed to save visitor pass"
        )

        return (
            jsonify({
                "error": "Failed to save visitor pass"
            }),
            500,
        )


# ============================================================
# RECEIPTS
# ============================================================

@app.route(
    "/api/receipts",
    methods=["GET", "POST"]
)
def handle_receipts_route():

    if request.method == "POST":

        data = get_json_object()

        if not data:

            return (
                jsonify({
                    "error": "No JSON object provided"
                }),
                400,
            )

        data.pop("createdByClerkId", None)

        data["createdByClerkId"] = g.clerk_user_id

        try:

            result = receipts_collection.insert_one(
                data
            )

            return jsonify({
                "message": "Receipt created",
                "id": str(result.inserted_id),
            }), 201

        except Exception:

            logger.exception(
                "Failed to create receipt"
            )

            return (
                jsonify({
                    "error": "Failed to create receipt"
                }),
                500,
            )

    role_name = current_user_role()

    query = (
        {}
        if role_name in ("admin", "sub_admin")
        else member_owned_filter()
    )

    receipts = (
        receipts_collection
        .find(query)
        .sort("_id", -1)
        .limit(50)
    )

    return jsonify([
        serialize_doc(receipt)
        for receipt in receipts
    ]), 200


# ============================================================
# ADMIN / GUARD - NUMBER PLATE RECOGNITION
# ============================================================

@app.route(
    "/api/admin/scan",
    methods=["POST"]
)
@require_roles("admin", "sub_admin")
def live_entry_test():

    data = get_json_object() or {}

    live_frame_b64 = data.get("liveFrame")

    if (
        not isinstance(live_frame_b64, str)
        or not live_frame_b64
    ):

        return (
            jsonify({
                "error": "No live frame provided"
            }),
            400,
        )

    try:

        from plate_ocr import extract_plate_from_base64

        detected_plate_text = sanitize_indian_plate(
            extract_plate_from_base64(
                live_frame_b64
            )
        )

        if (
            detected_plate_text
            and len(detected_plate_text) >= 4
        ):

            cursor = (
                visits_collection
                .find({
                    "vehicleNo": {
                        "$exists": True,
                        "$ne": "",
                    },
                    "status": {
                        "$in": [
                            "pending_review",
                            "approved",
                        ]
                    },
                })
                .sort([("_id", -1)])
            )

            for visitor in cursor:

                db_plate = visitor.get(
                    "vehicleNo",
                    ""
                )

                fuzzy_regex = build_db_fuzzy_regex(
                    db_plate
                )

                if (
                    fuzzy_regex
                    and re.search(
                        fuzzy_regex,
                        detected_plate_text
                    )
                ):

                    visitor_id = visitor.get("_id")

                    visits_collection.update_one(
                        {
                            "_id": visitor_id
                        },
                        {
                            "$set": {
                                "status": "approved"
                            }
                        },
                    )

                    auto_sync_receipt_status(
                        visitor_id,
                        visitor,
                        "approved"
                    )

                    visitor["status"] = "approved"

                    return jsonify({
                        "success": True,
                        "message": (
                            f"Matched Vehicle Plate: {db_plate}"
                        ),
                        "visitor": serialize_doc(visitor),
                    }), 200

        return (
            jsonify({
                "success": False,
                "message": (
                    "No matching vehicle found. Access Denied."
                ),
            }),
            404,
        )

    except Exception:

        logger.exception(
            "Vehicle plate scan failed"
        )

        return (
            jsonify({
                "success": False,
                "message": "Server processing error",
            }),
            500,
        )


# ============================================================
# ADMIN - UPDATE VISITOR STATUS
# ============================================================

@app.route(
    "/api/admin/status/<visitor_id>",
    methods=["PUT"]
)
@require_roles("admin", "sub_admin")
def update_visitor_status(visitor_id):

    data = get_json_object() or {}

    new_status = data.get("status")

    if (
        not isinstance(new_status, str)
        or not new_status.strip()
    ):

        return (
            jsonify({
                "error": "No valid status provided"
            }),
            400,
        )

    visitor_object_id = parse_object_id(
        visitor_id
    )

    if visitor_object_id is None:

        return (
            jsonify({
                "error": "Invalid visitor ID"
            }),
            400,
        )

    try:

        visit = visits_collection.find_one(
            {
                "_id": visitor_object_id
            }
        )

        if not visit:

            return (
                jsonify({
                    "success": False,
                    "error": "Visitor not found",
                }),
                404,
            )

        result = visits_collection.update_one(
            {
                "_id": visitor_object_id
            },
            {
                "$set": {
                    "status": new_status.strip()
                }
            },
        )

        if (
            result.modified_count == 1
            or result.matched_count == 1
        ):

            auto_sync_receipt_status(
                visitor_object_id,
                visit,
                new_status.strip()
            )

            return jsonify({
                "success": True,
                "message": (
                    f"Status updated to {new_status.strip()}"
                ),
            }), 200

        return (
            jsonify({
                "success": False,
                "error": "Visitor not found",
            }),
            404,
        )

    except Exception:

        logger.exception(
            "Failed to update visitor status"
        )

        return (
            jsonify({
                "success": False,
                "error": "Failed to update visitor status",
            }),
            500,
        )


# ============================================================
# ADMIN - FETCH VISITORS
# ============================================================

@app.route(
    "/api/admin/visitors",
    methods=["GET"]
)
@require_roles("admin", "sub_admin")
def get_visitors():

    try:

        visitors = (
            visits_collection
            .find()
            .sort("_id", -1)
            .limit(100)
        )

        return jsonify([
            serialize_doc(visitor)
            for visitor in visitors
        ]), 200

    except Exception:

        logger.exception(
            "Failed to fetch visitors"
        )

        return (
            jsonify({
                "error": "Failed to fetch visitors"
            }),
            500,
        )


# ============================================================
# ADMIN - UPDATE / DELETE VISITORS
# ============================================================

@app.route(
    "/api/admin/visitors/<visitor_id>",
    methods=["PUT", "DELETE"]
)
@require_roles("admin", "sub_admin")
def manage_visitor(visitor_id):

    visitor_object_id = parse_object_id(
        visitor_id
    )

    if visitor_object_id is None:

        return (
            jsonify({
                "success": False,
                "error": "Invalid visitor ID",
            }),
            400,
        )

    try:

        if request.method == "DELETE":

            deleted = visits_collection.delete_one(
                {
                    "_id": visitor_object_id
                }
            )

            if deleted.deleted_count != 1:

                return (
                    jsonify({
                        "success": False,
                        "error": "Visitor not found",
                    }),
                    404,
                )

            receipts_collection.delete_many({
                "$or": [
                    {
                        "visitorId": str(visitor_object_id)
                    },
                    {
                        "visitId": str(visitor_object_id)
                    },
                ]
            })

            return jsonify({
                "success": True,
                "message": "Visitor deleted successfully",
            }), 200

        data = get_json_object()

        if data is None:

            return (
                jsonify({
                    "error": "No JSON object provided"
                }),
                400,
            )

        data.pop("_id", None)

        data.pop(
            "createdByClerkId",
            None
        )

        visit = visits_collection.find_one(
            {
                "_id": visitor_object_id
            }
        )

        if not visit:

            return (
                jsonify({
                    "success": False,
                    "error": "Visitor not found",
                }),
                404,
            )

        visits_collection.update_one(
            {
                "_id": visitor_object_id
            },
            {
                "$set": data
            },
        )

        if "status" in data:

            auto_sync_receipt_status(
                visitor_object_id,
                visit,
                data["status"]
            )

        return jsonify({
            "success": True,
            "message": "Visitor updated successfully",
        }), 200

    except Exception:

        logger.exception(
            "Failed to manage visitor"
        )

        return (
            jsonify({
                "success": False,
                "error": "Failed to manage visitor",
            }),
            500,
        )


# ============================================================
# STUDENT REGISTRATION
# ============================================================

@app.route(
    "/api/students",
    methods=["POST", "GET"]
)
def handle_students():

    if request.method == "GET":

        role_name = current_user_role()

        if role_name not in ("admin", "sub_admin"):

            return (
                jsonify({
                    "error": "Insufficient permissions"
                }),
                403,
            )

        try:

            students = (
                students_collection
                .find()
                .sort("_id", -1)
            )

            return jsonify([
                serialize_doc(student)
                for student in students
            ]), 200

        except Exception:

            logger.exception(
                "Failed to fetch students"
            )

            return (
                jsonify({
                    "error": "Failed to fetch students"
                }),
                500,
            )

    data = get_json_object()

    if not data:

        return (
            jsonify({
                "error": "No JSON object provided"
            }),
            400,
        )

    valid_names, name_message = (
        validate_names_in_payload(data)
    )

    if not valid_names:

        return jsonify({
            "error": name_message
        }), 400

    valid_contacts, contact_message = (
        validate_contacts_in_payload(data)
    )

    if not valid_contacts:

        return jsonify({
            "error": contact_message
        }), 400

    valid_student, student_message = (
        validate_student_registration_data(data)
    )

    if not valid_student:

        return jsonify({
            "error": student_message
        }), 400

    data.pop("createdByClerkId", None)

    data["createdByClerkId"] = g.clerk_user_id

    data["submittedAt"] = datetime.now(
        timezone.utc
    )

    try:

        result = students_collection.insert_one(
            data
        )

        return jsonify({
            "message": "Student Registration Saved",
            "id": str(result.inserted_id),
        }), 201

    except Exception:

        logger.exception(
            "Failed to save student registration"
        )

        return (
            jsonify({
                "error": "Failed to save student registration"
            }),
            500,
        )


# ============================================================
# GUARD - FACE VERIFICATION
# ============================================================

@app.route(
    "/api/guard/verify-face",
    methods=["POST"]
)
@require_roles("admin", "sub_admin")
def verify_authorized_face():

    data = get_json_object() or {}

    live_frame_b64 = data.get("liveFrame")

    target_student_id = data.get("studentId")

    if (
        not isinstance(live_frame_b64, str)
        or not live_frame_b64
    ):

        return (
            jsonify({
                "error": "No live frame provided"
            }),
            400,
        )

    if (
        target_student_id is not None
        and not validate_student_id_format(
            target_student_id
        )
    ):

        return (
            jsonify({
                "error": "Invalid Student ID format"
            }),
            400,
        )

    try:

        expected_student_ids = []

        pending_visits_pool = []

        search_status = {
            "$in": [
                "pending_review",
                "approved",
            ]
        }

        # ----------------------------------------------------
        # SEARCH VISITOR
        # ----------------------------------------------------

        if target_student_id:

            expected_student_ids = [
                target_student_id
            ]

            visit = visits_collection.find_one(
                {
                    "$or": [
                        {
                            "hostId": target_student_id
                        },
                        {
                            "studentId": target_student_id
                        },
                    ],
                    "status": search_status,
                },
                sort=[("_id", -1)],
            )

            if visit:

                pending_visits_pool.append(
                    visit
                )

        else:

            pending_visits_pool = list(
                visits_collection
                .find({
                    "status": search_status
                })
                .sort([("_id", -1)])
                .limit(50)
            )

            if not pending_visits_pool:

                return (
                    jsonify({
                        "success": False,
                        "message": "No pending visitors found.",
                    }),
                    404,
                )

            for visit in pending_visits_pool:

                student_id = (
                    visit.get("hostId")
                    or visit.get("studentId")
                )

                if (
                    student_id
                    and student_id not in expected_student_ids
                ):

                    expected_student_ids.append(
                        student_id
                    )

        if not expected_student_ids:

            return (
                jsonify({
                    "success": False,
                    "message": (
                        "No valid Student IDs found in pending visits."
                    ),
                }),
                404,
            )

        # ----------------------------------------------------
        # FIND REGISTERED STUDENTS
        # ----------------------------------------------------

        students = list(
            students_collection.find({
                "studentId": {
                    "$in": expected_student_ids
                }
            })
        )

        registered_ids = [
            student.get("studentId")
            for student in students
            if (
                student.get("authorizedPersons")
                or student.get("studentPhoto")
            )
        ]

        missing_ids = [
            student_id
            for student_id in expected_student_ids
            if student_id not in registered_ids
        ]

        if not registered_ids:

            missing_text = ", ".join(
                missing_ids
            )

            return (
                jsonify({
                    "success": False,
                    "message": (
                        "Access Denied: Student Registration "
                        f"has not been filled for Student ID "
                        f"'{missing_text}'. The visitor is not authorized."
                    ),
                }),
                404,
            )

        # ----------------------------------------------------
        # PREPARE AUTHORIZED PERSON PHOTOS
        # ----------------------------------------------------

        flattened_persons = []

        for student in students:

            if (
                student.get("studentId")
                not in registered_ids
            ):
                continue

            if student.get("studentPhoto"):

                flattened_persons.append({
                    "visitorPhoto": student.get(
                        "studentPhoto"
                    ),
                    "visitorName": student.get(
                        "studentName",
                        "Student (Self)"
                    ),
                    "relation": "Self",
                    "studentName": student.get(
                        "studentName",
                        "N/A"
                    ),
                    "studentId": student.get(
                        "studentId",
                        "N/A"
                    ),
                })

            for person in student.get(
                "authorizedPersons",
                []
            ):

                if (
                    isinstance(person, dict)
                    and person.get("photo")
                ):

                    flattened_persons.append({
                        "visitorPhoto": person.get(
                            "photo"
                        ),
                        "visitorName": person.get(
                            "name"
                        ),
                        "relation": person.get(
                            "relation",
                            "N/A"
                        ),
                        "studentName": student.get(
                            "studentName",
                            "N/A"
                        ),
                        "studentId": student.get(
                            "studentId",
                            "N/A"
                        ),
                    })

        if not flattened_persons:

            return (
                jsonify({
                    "success": False,
                    "message": (
                        "Access Denied: No valid face photos "
                        "found in Student Registration."
                    ),
                }),
                404,
            )

        # ----------------------------------------------------
        # DEEPFACE FACE MATCHING
        # ----------------------------------------------------

        from face_scanner import match_face_in_db

        matched_person = match_face_in_db(
            live_frame_b64,
            flattened_persons
        )

        if not matched_person:

            return (
                jsonify({
                    "success": False,
                    "message": (
                        "Access Denied: The person is not among "
                        "the authorized persons for the specified student."
                    ),
                }),
                404,
            )

        matched_student_id = (
            matched_person.get("studentId")
        )

        latest_visit = next(
            (
                visit
                for visit in pending_visits_pool
                if (
                    visit.get("hostId")
                    or visit.get("studentId")
                ) == matched_student_id
            ),
            None,
        )

        if not latest_visit:

            return (
                jsonify({
                    "success": False,
                    "message": (
                        "Face recognized, but it could not be "
                        "linked to a pending visitor form "
                        "for that Student ID."
                    ),
                }),
                404,
            )

        # ----------------------------------------------------
        # APPROVE VISITOR
        # ----------------------------------------------------

        visitor_id = latest_visit.get("_id")

        visits_collection.update_one(
            {
                "_id": visitor_id
            },
            {
                "$set": {
                    "status": "approved"
                }
            },
        )

        auto_sync_receipt_status(
            visitor_id,
            latest_visit,
            "approved"
        )

        latest_visit["status"] = "approved"

        return jsonify({
            "success": True,
            "message": (
                "Authorized Person Verified: "
                f"{matched_person.get('visitorName')}"
            ),
            "person": matched_person,
            "visitor": serialize_doc(latest_visit),
        }), 200

    except Exception:

        logger.exception(
            "Face verification failed"
        )

        return (
            jsonify({
                "success": False,
                "error": "Face verification failed",
            }),
            500,
        )


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

# Vercel uses the top-level Flask variable: app

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv("PORT", "5000")
        ),
        debug=os.getenv("FLASK_DEBUG") == "1",
        use_reloader=False,
    )