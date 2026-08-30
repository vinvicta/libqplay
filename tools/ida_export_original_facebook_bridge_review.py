#!/usr/bin/env python3
"""Export the original 1.8 Facebook native and Java bridge review.

The exporter is read-only. It records the native callbacks that connect the
script table to the bundled Facebook SDK, together with behavior checked in
the private DEX smali. It does not execute a script, start a login flow, read
a live token, open a socket, or contact Facebook.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import ida_funcs
import ida_hexrays
import idaapi
import idautils
import idc


TARGETS = [
    ("0x245f40", "main_android_initStaticScriptVars_void", "Android script table owner"),
    ("0x24025c", "JNI_getNewFacebookPermissions", "Facebook permission getter bridge"),
    ("0x240380", "JNI_getNewFacebookToken", "Facebook access-token getter bridge"),
    ("0x240884", "JNI_isNewFacebookAvailable", "Facebook availability bridge"),
    ("0x2413cc", "JNI_getNewFacebookSessionState", "Facebook session-state getter bridge"),
    ("0x2415b4", "JNI_logoutFromNewFacebook", "Facebook logout bridge"),
    ("0x24296c", "JNI_requestNewFacebookGraph", "Facebook Graph request bridge"),
    ("0x242a88", "JNI_requestNewFacebookRights", "Facebook permission-request bridge"),
    ("0x242bb4", "JNI_loginToNewFacebook", "Facebook login bridge"),
    ("0x246104", "MainAndroid_script_requestnewfacebookgraph2", "Facebook Graph upload bridge"),
]

DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_facebook_bridge_review_20260830.json"
)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def effective_callers(address: int) -> list[dict]:
    callers = []
    for reference in idautils.XrefsTo(address, 0):
        caller = ida_funcs.get_func(reference.frm)
        if caller is None:
            continue
        callers.append(
            {
                "callsite": "0x%x" % reference.frm,
                "caller": "0x%x" % caller.start_ea,
                "caller_name": idc.get_func_name(caller.start_ea) or "",
            }
        )
    unique = {(item["caller"], item["callsite"]): item for item in callers}
    return sorted(
        unique.values(),
        key=lambda item: (int(item["caller"], 16), int(item["callsite"], 16)),
    )[:250]


def export_function(address: int, expected_name: str, role: str) -> dict:
    current_name = idc.get_func_name(address) or ""
    if current_name != expected_name:
        raise RuntimeError(
            "unexpected function name at %s: %s (expected %s)"
            % (hex(address), current_name, expected_name)
        )
    decompiled = ida_hexrays.decompile(address)
    if decompiled is None:
        raise RuntimeError("Hex-Rays could not decompile %s" % hex(address))
    code = str(decompiled)
    function = ida_funcs.get_func(address)
    return {
        "address": "0x%x" % address,
        "name": current_name,
        "role": role,
        "function_start": "0x%x" % function.start_ea if function else None,
        "function_end": "0x%x" % function.end_ea if function else None,
        "code_sha256": sha256_text(code),
        "code_bytes": len(code.encode("utf-8")),
        "callers": effective_callers(address),
        "code": code,
    }


SCRIPT_SURFACE = {
    "owner": "main_android_initStaticScriptVars_void",
    "table_va": "0x38b2d0",
    "registered_function_count": 44,
    "source": "IDA script_table_inventory.json plus active IDA database",
    "relevant_entries": [
        {
            "script_name": "isnewfacebookavailable",
            "callback_va": "0x240884",
            "native_signature": "isNewFacebookAvailable()Z",
            "behavior": "The bundled Natives implementation returns true.",
        },
        {
            "script_name": "logintonewfacebook",
            "callback_va": "0x242bb4",
            "native_signature": "loginToNewFacebook(I[B)V",
            "behavior": "Passes the force-style integer and comma permission text to the activity.",
        },
        {
            "script_name": "logoutfromnewfacebook",
            "callback_va": "0x2415b4",
            "native_signature": "logoutFromNewFacebook()V",
            "behavior": "Closes the active session and clears its token information when open.",
        },
        {
            "script_name": "getnewfacebooksessionstate",
            "callback_va": "0x2413cc",
            "native_signature": "getNewFacebookSessionState()I",
            "behavior": "Returns the activity's mapped session state integer.",
        },
        {
            "script_name": "getnewfacebooktoken",
            "callback_va": "0x240380",
            "native_signature": "getNewFacebookToken()[B",
            "behavior": "Returns the active Facebook access token when the session is open.",
        },
        {
            "script_name": "getnewfacebookpermissions",
            "callback_va": "0x24025c",
            "native_signature": "getNewFacebookPermissions()[B",
            "behavior": "Returns the active session permissions as escaped comma text.",
        },
        {
            "script_name": "requestnewfacebookrights",
            "callback_va": "0x242a88",
            "native_signature": "requestNewFacebookRights(I[B)V",
            "behavior": "Requests script-supplied read or publish permissions on an open session.",
        },
        {
            "script_name": "requestnewfacebookgraph",
            "callback_va": "0x24296c",
            "native_signature": "requestNewFacebookGraph([B)V",
            "behavior": "Starts a default GET request for a script-supplied Graph path.",
        },
        {
            "script_name": "requestnewfacebookgraph2",
            "callback_va": "0x246104",
            "native_signature": "requestNewFacebookGraph2([B[B[B)V",
            "behavior": "Starts a Graph request and can convert native game files into image or file attachments.",
        },
        {
            "script_name": "canshowfacebooksharedialog",
            "callback_va": "0x240a1c",
            "native_signature": "canShowFacebookShareDialog([B[B[B[B[B[B)Z",
            "behavior": "Reports whether the activity has an open Facebook session through the WebDialog check.",
        },
        {
            "script_name": "showfacebooksharedialog",
            "callback_va": "0x242504",
            "native_signature": "showFacebookShareDialog([B[B[B[B[B[B)V",
            "behavior": "Builds a feed dialog request from link, name, caption, description, and picture text.",
        },
        {
            "script_name": "canshowfacebookwebdialog",
            "callback_va": "0x2407fc",
            "native_signature": "canShowFacebookWebDialog()Z",
            "behavior": "Returns true only when the active Facebook session is open.",
        },
        {
            "script_name": "showfacebookwebdialog",
            "callback_va": "0x24233c",
            "native_signature": "showFacebookWebDialog([B[B)V",
            "behavior": "Passes an action and comma-encoded parameters to the Facebook WebDialog.",
        },
    ],
}


JAVA_OBSERVATIONS = [
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "getNewFacebookToken()",
        "source": "original DEX smali",
        "behavior": [
            "Reads Session.getActiveSession().",
            "Returns Session.getAccessToken() only when the session exists and is opened.",
            "Returns an empty string when no open session exists.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "getNewFacebookPermissions()",
        "source": "original DEX smali",
        "behavior": [
            "Reads the open session permission list.",
            "Joins permission names with commas and applies the activity's quote escaping before returning them.",
            "Returns an empty string when no open session exists.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "getNewFacebookSessionState()",
        "source": "original DEX smali",
        "behavior": [
            "Creates and registers a Session when no active session exists.",
            "Maps CREATED to 0, CREATED_TOKEN_LOADED to 1, OPENING to 2, OPENED to 0x201, OPENED_TOKEN_UPDATED to 0x202, CLOSED_LOGIN_FAILED to 0x101, and CLOSED to 0x102.",
            "Returns -1 for an unrecognized state.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "loginToNewFacebook(boolean, java.lang.String)",
        "source": "original DEX smali",
        "behavior": [
            "Returns immediately when the active session is already open.",
            "Parses comma-separated requested permissions and removes trailing empty entries.",
            "Builds an OpenRequest with those permissions and a status callback, then calls Session.openForRead().",
            "The Boolean controls whether a newly built session may proceed when it is not in CREATED_TOKEN_LOADED state.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "requestNewFacebookRights(boolean, java.lang.String)",
        "source": "original DEX smali",
        "behavior": [
            "Requires an existing open active session.",
            "Stores and parses the caller's comma-separated permission text, removing trailing empty entries.",
            "Uses requestNewPublishPermissions when the Boolean is true and requestNewReadPermissions otherwise.",
            "The status callback reports the requested text plus a Boolean indicating whether every requested permission is now present.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "requestNewFacebookGraphWithParams(java.lang.String, java.lang.String, android.os.Bundle)",
        "source": "original DEX smali",
        "behavior": [
            "Requires an open active session and otherwise returns without an event.",
            "Maps the exact strings POST and DELETE to those HttpMethod values and maps every other method string to GET.",
            "Constructs com.facebook.Request with the caller's Graph path, Bundle, and callback, then calls executeAsync().",
        ],
    },
    {
        "class": "com.facebook.Request",
        "method": "getUrlForSingleRequest and addCommonParameters",
        "source": "original DEX smali",
        "behavior": [
            "Uses the default Graph API version v2.1 unless the path already matches the version pattern ^/?v\\d+\\.\\d+/(.*).",
            "Builds the normal endpoint as https://graph.facebook.com/<version>/<path>; POST paths ending in /videos use the graph-video host.",
            "Adds the active session access_token to the request Bundle when the caller did not provide one, plus sdk=android and format=json.",
            "Uses HttpURLConnection, sets the Facebook SDK headers, and enables chunked streaming for POST bodies.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity",
        "method": "requestNewFacebookGraph2(java.lang.String, java.lang.String, java.lang.String)",
        "source": "original DEX smali",
        "behavior": [
            "Parses alternating comma-text keys and values into a Bundle.",
            "Values prefixed image: are Base64-decoded and passed through BitmapFactory.decodeByteArray before being stored as a Bitmap.",
            "Values prefixed file: are Base64-decoded and stored as byte arrays; other values remain strings.",
            "The native wrapper handles image: and file: values before this method by resolving a game file, reading it, Base64-encoding it, and replacing the value.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity$24",
        "method": "call(Session, SessionState, Exception)",
        "source": "original DEX smali",
        "behavior": [
            "Schedules onNewFaceBookState with the mapped state integer on the GL thread.",
            "When a permission request is pending, checks every requested permission against Session.getPermissions().",
            "Schedules onNewFaceBookRights with the escaped original permission text and 1 only when all requested entries are present, otherwise 0.",
            "Clears the pending permission fields after scheduling the result.",
        ],
    },
    {
        "class": "com.quattroplay.GraalClassic.QPlayActivity$25$1",
        "method": "onCompleted(Response)",
        "source": "original DEX smali",
        "behavior": [
            "Starts a comma-text result with the escaped requested Graph path.",
            "Appends the GraphObject inner JSONObject text when one exists.",
            "Schedules onNewFaceBookGraph on the GL thread; the reviewed callback does not append a FacebookException string when the response has no GraphObject.",
        ],
    },
]


OBSERVATIONS = [
    {
        "address": "0x240380",
        "classification": "credential-like token exposure",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The main_android script table maps getnewfacebooktoken to JNI_getNewFacebookToken.",
            "The JNI wrapper calls the Java getNewFacebookToken()[B method and copies the result into a native TString.",
            "QPlayActivity returns the active Session access token when the session is open.",
        ],
        "interpretation": "An activated script can receive the bearer token for the current Facebook session through a normal script callback.",
    },
    {
        "address": "0x24296c",
        "classification": "privileged Graph request surface",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The script table maps requestnewfacebookgraph to JNI_requestNewFacebookGraph.",
            "The Java activity requires an open active session, accepts a caller-supplied Graph path, and starts an asynchronous Facebook Request.",
            "The SDK builds requests for the HTTPS Graph host and adds the active access token when absent from the Bundle.",
        ],
        "interpretation": "The script API can perform authenticated Facebook Graph reads and writes subject to the session's granted permissions and Facebook's server policy.",
    },
    {
        "address": "0x246104",
        "classification": "local-resource to Facebook upload path",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The native graph2 callback recognizes image: and file: parameter values.",
            "It resolves the suffix as a game file, loads the resource, Base64-encodes its bytes, and replaces the parameter before calling Java.",
            "Java converts image: data into a Bitmap and file: data into a byte array in the request Bundle.",
        ],
        "interpretation": "A script can combine access to a game-readable resource with an authenticated Facebook upload request, although this path is not an arbitrary raw filesystem reader by itself.",
    },
    {
        "address": "0x242a88",
        "classification": "script-controlled permission request",
        "confidence": "confirmed-static-plus-dex",
        "evidence": [
            "The script table maps requestnewfacebookrights to JNI_requestNewFacebookRights.",
            "The Java method accepts arbitrary comma-separated permission text and selects read or publish permission requests from a Boolean flag.",
            "No local permission-name allowlist appears in the reviewed method; Facebook still mediates the resulting user prompt and server decision.",
        ],
        "interpretation": "A script can ask the user for additional Facebook capabilities through the client UI, which increases the impact of a compromised or untrusted script package.",
    },
    {
        "address": "0x245f40",
        "classification": "script capability registration",
        "confidence": "confirmed-static-plus-inventory",
        "evidence": [
            "main_android_initStaticScriptVars_void registers 44 Android functions through the table at 0x38b2d0.",
            "The relevant Facebook entries and callback addresses match the repository script_table_inventory.json records.",
        ],
        "interpretation": "These are intended script-visible capabilities, not merely dead JNI helpers.",
    },
]


FINDINGS = [
    {
        "id": "ANDROID-FB-001",
        "severity": "high",
        "confidence": "confirmed-static-plus-dex",
        "title": "An activated script can read the active Facebook bearer token",
        "evidence": [
            "getnewfacebooktoken is registered in the main_android script table and points to JNI_getNewFacebookToken.",
            "The JNI wrapper copies QPlayActivity.getNewFacebookToken() into a native script value.",
            "The Java method returns Session.getAccessToken() for an open active session.",
        ],
        "impact": "Any script that reaches this capability can copy the current Facebook bearer token and use it outside the intended game feature boundary. A bearer token can authorize actions covered by the granted session permissions until it expires or is revoked.",
        "limits": "The review did not execute a script, perform a Facebook login, capture a token, or send the token to an endpoint. Reachability depends on the script package and the native script runtime trust model. No real token is included in this artifact.",
    },
    {
        "id": "ANDROID-FB-002",
        "severity": "medium",
        "confidence": "confirmed-static-plus-dex",
        "title": "The script API can issue authenticated Graph GET, POST, and DELETE requests",
        "evidence": [
            "requestnewfacebookgraph and requestnewfacebookgraph2 are script-table entries.",
            "The activity accepts exact POST and DELETE method strings and treats all other values as GET.",
            "The bundled Facebook SDK targets the HTTPS Graph host and automatically inserts the active session access_token when the caller has not supplied one.",
        ],
        "impact": "A compromised or untrusted script package can use the user's granted Facebook permissions for reads and state-changing Graph operations, including deletion requests accepted by Facebook.",
        "limits": "The request still requires an open session and is subject to the permission set and Facebook server authorization. The review did not contact Facebook or prove that any particular Graph path is accepted by the historical API version.",
    },
    {
        "id": "ANDROID-FB-003",
        "severity": "medium",
        "confidence": "confirmed-static-plus-dex",
        "title": "The graph2 bridge joins game-resource reads to authenticated uploads",
        "evidence": [
            "The native callback resolves image: and file: values through TResourceFunctions_getGameFile and TStream_LoadFromFile.",
            "It Base64-encodes the loaded bytes and forwards them to Java.",
            "Java turns image: values into Bitmaps and file: values into byte-array Bundle entries for the Facebook Request.",
        ],
        "impact": "A script with access to this callback can upload eligible game resources through the user's active Facebook session. This extends the impact of a script compromise beyond token exposure alone.",
        "limits": "The path is based on game-file resource resolution, not a demonstrated unrestricted filesystem read. No file was uploaded and no external network request was made during this review.",
    },
    {
        "id": "ANDROID-FB-004",
        "severity": "medium",
        "confidence": "confirmed-static-plus-dex",
        "title": "Scripts can request additional Facebook read or publish permissions",
        "evidence": [
            "requestnewfacebookrights is a registered script callback.",
            "The Java method accepts caller-supplied comma-separated permission names and selects requestNewReadPermissions or requestNewPublishPermissions from the Boolean flag.",
            "The status result is returned to native script code after the session permission list is checked.",
        ],
        "impact": "A malicious script can trigger permission prompts for capabilities outside the original feature's narrow purpose and can attempt to obtain publish permissions from the user.",
        "limits": "The user-facing Facebook flow and Facebook's server-side policy still mediate the request. The review did not display a prompt or obtain new permissions.",
    },
]


def main() -> None:
    if not idaapi.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is not available")
    functions = [
        export_function(int(address, 16), name, role)
        for address, name, role in TARGETS
    ]
    result = {
        "schema": "libqplay.original-facebook-bridge-review.v1",
        "artifact": "original_facebook_bridge_review_20260830",
        "scope": "read-only review of the original 1.8 Facebook script, JNI, and bundled SDK bridge",
        "network_contacted": False,
        "scripts_executed": False,
        "facebook_login_performed": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8",
        },
        "script_surface": SCRIPT_SURFACE,
        "java_observations": JAVA_OBSERVATIONS,
        "observations": OBSERVATIONS,
        "findings": FINDINGS,
        "functions": functions,
        "interpretation": [
            "The Facebook path is separate from the native Graal connector and its CyaSSL trust bundle.",
            "The script bridge is intentionally powerful enough to log in, ask for permissions, read the token, issue Graph requests, and report results back to native script code.",
            "The bundled SDK uses HTTPS Graph endpoints by default, but HTTPS transport does not prevent a trusted or compromised script from misusing the active session token exposed by the API.",
            "A repair should remove direct token getters from script scope, restrict Graph operations to named game features, keep upload sources allowlisted, and require explicit user intent for permission changes.",
        ],
    }
    output = os.environ.get("IDA_FACEBOOK_BRIDGE_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
