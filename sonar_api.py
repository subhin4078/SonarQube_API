from flask import Flask, request, jsonify, Response
import subprocess
import os
import requests
import re
import shutil
import json
import time
import zipfile
from collections import OrderedDict

SONAR_TOKEN = os.environ.get("SONAR_TOKEN")
SONAR_HOST = os.environ.get("SONAR_HOST_URL", "http://localhost:9000")

app = Flask(__name__)

# Helper function: to return error responses in a consistent format
def error_response(message, code=400, **kwargs):
    resp = {"error": message}
    resp.update(kwargs)
    return jsonify(resp), code

# Helper function: to call SonarQube API
def sonar_api(endpoint, params):
    try:
        token = request.headers.get('X-Sonar-Token')
        resp = requests.get(
            f"{SONAR_HOST}{endpoint}",
            params = params,
            auth = (token, ""),
            timeout = 15
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

# Helper function: to check if a project exists in SonarQube
def project_exists(project_key):
    data = sonar_api("/api/components/show", {"component": project_key})
    return "component" in data

# Helper function: to extract project key from data or filename
def get_project_key(data, filename=None):
    if 'project_key' in data:
        return data['project_key']
    if 'git_url' in data:
        m = re.search(r'/([^/]+?)(\.git)?$', data['git_url'])
        return m.group(1) if m else "default_git_project"
    if filename:
        return os.path.splitext(os.path.basename(filename))[0]
    # No project key found, then will return an error message later on
    return None 

# Helper function: to prepare the scan directory and arguments
def prepare_scan(data, header_token):
    project_key = get_project_key(data)
    project_name = data.get("project_name")
    if not project_name:
        return None, None, error_response("Missing required field: project_name", 400)
    if not project_key:
        return None, None, error_response("Missing required field: project_key", 400)

    if "git_url" in data:
        git_url = data["git_url"]
        project_dir = f"/tmp/git_project_{project_key}"
        if os.path.exists(project_dir):
            shutil.rmtree(project_dir)
        os.makedirs(project_dir, exist_ok=True)
        result = subprocess.run(["git", "clone", "--depth", "1", git_url, project_dir], capture_output=True, text=True)
        if result.returncode != 0:
            return None, project_dir, error_response("Failed to clone git repository", 500, details=result.stderr or result.stdout)
        scan_args = [
            "/opt/sonar-scanner/bin/sonar-scanner",
            f"-Dsonar.projectBaseDir={project_dir}",
            f"-Dsonar.projectKey={project_key}",
            f"-Dsonar.projectName={project_name}",
            f"-Dsonar.login={header_token}"
        ]
        return scan_args, project_dir, None

    elif "code" in data:
        code = data["code"]
        code_filename = data.get("filename", f"{project_key}_source.py")
        project_dir = f"/tmp/code_project_{project_key}"
        if os.path.exists(project_dir):
            shutil.rmtree(project_dir)
        os.makedirs(project_dir, exist_ok=True)
        with open(os.path.join(project_dir, code_filename), "w", encoding='utf-8') as f_code:
            f_code.write(code)
        scan_args = [
            "/opt/sonar-scanner/bin/sonar-scanner",
            f"-Dsonar.projectBaseDir={project_dir}",
            f"-Dsonar.projectKey={project_key}",
            f"-Dsonar.projectName={project_name}",
            f"-Dsonar.sources={code_filename}",
            f"-Dsonar.login={header_token}"
        ]
        return scan_args, project_dir, None

    else:
        return None, None, error_response("Invalid JSON payload. Expecting 'git_url' or 'code'.", 400)

# Helper function: to get SonarQube report for a project
def get_sonar_report(project_key):
    def safe_int(val): return int(float(val or 0))
    def safe_float(val): return float(val or 0)
    project_info = sonar_api("/api/components/show", {"component": project_key})
    analyses = sonar_api("/api/project_analyses/search", {"project": project_key, "ps": 1})
    metrics = sonar_api("/api/measures/component", {
        "component": project_key,
        "metricKeys": "bugs,vulnerabilities,code_smells,duplicated_lines_density,coverage,ncloc,sqale_index"
    })
    issues = sonar_api("/api/issues/search", {"componentKeys": project_key, "ps": 500})
    quality_gate = sonar_api("/api/qualitygates/project_status", {"projectKey": project_key})

    metrics_summary = {}
    if isinstance(metrics, dict) and not metrics.get("error"):
        vals = {x["metric"]: x.get("value") for x in metrics.get("component", {}).get("measures", [])}
        metrics_summary = {
            "bugs": safe_int(vals.get("bugs")),
            "vulnerabilities": safe_int(vals.get("vulnerabilities")),
            "code_smells": safe_int(vals.get("code_smells")),
            "duplicated_lines_density": safe_float(vals.get("duplicated_lines_density")),
            "coverage": safe_float(vals.get("coverage")),
            "lines_of_code": safe_int(vals.get("ncloc")),
            "sqale_index": safe_int(vals.get("sqale_index"))
        }

    issues_list = []
    if isinstance(issues, dict) and not issues.get("error"):
        for i in issues.get("issues", []):
            issues_list.append({
                "key": i.get("key"),
                "type": i.get("type"),
                "severity": i.get("severity"),
                "message": i.get("message"),
                "component": i.get("component"),
                "line": i.get("line"),
                "effort_minutes": i.get("effort")
            })

    quality_gate_status = {}
    qgs = {}
    if isinstance(quality_gate, dict) and not quality_gate.get("error"):
        qgs = quality_gate.get("projectStatus", {})
        quality_gate_status = {
            "status": qgs.get("status"),
            "conditions": [
                {
                    "metric": c.get("metricKey"),
                    "actual_value": c.get("actualValue"),
                    "threshold": c.get("errorThreshold") or c.get("warningThreshold"),
                    "status": c.get("status")
                }
                for c in qgs.get("conditions", [])
            ]
        }

    project = {}
    if isinstance(project_info, dict) and not project_info.get("error"):
        comp = project_info.get("component", {})
        ana_list = analyses.get("analyses", []) if isinstance(analyses, dict) and not analyses.get("error") else []
        ana = ana_list[0] if ana_list else {}
        project = {
            "name": comp.get("name"),
            "key": comp.get("key"),
            "analysis_id": ana.get("key"),
            "status": qgs.get("status"),
            "analysis_date": ana.get("date")
        }
    else:
        project = project_info

    return OrderedDict([
        ("project", project),
        ("metrics_summary", metrics_summary),
        ("issues", issues_list),
        ("quality_gate_status", quality_gate_status)
    ])

# Endpoint: Scan
@app.route('/scan', methods=['POST'])
def scan():
    try:
        # error message: missing required header
        if 'X-Sonar-Token' not in request.headers:
            return error_response("Missing required header: X-Sonar-Token", 401)
        header_token = request.headers.get('X-Sonar-Token')

        # error message: invalid SonarQube token in header
        if not header_token or (SONAR_TOKEN and header_token != SONAR_TOKEN):
            return error_response("Invalid SonarQube token in header.", 401)

        # --- Get project_key early for existence check ---
        project_key = None
        if 'file' in request.files:
            project_key = request.form.get("project_key")
        else:
            data = request.get_json(silent=True) or {}
            if isinstance(data, dict):
                project_key = get_project_key(data)

        # error message: missing project_key
        if not project_key:
            return error_response("Missing required field: project_key", 400)
        
        # error message: project_key already exists
        if project_exists(project_key):
            return error_response(f"Project '{project_key}' already exists. Please use a different project_key.")

        # --- Handle file upload (zip) ---
        if 'file' in request.files:
            files = request.files.getlist('file')
            
            # error message: no file selected or multiple files uploaded
            if len(files) > 1:
                return error_response("Only one zip file is allowed.", 400)
            f = files[0]
            if not f or not f.filename:
                return error_response("No file selected or filename is empty")

            filename = os.path.basename(f.filename)
            upload_base_dir = "/tmp/sonar_file_uploads"
            project_dir = os.path.join(upload_base_dir, filename + "_scan")
            os.makedirs(project_dir, exist_ok=True)
            cleanup_dir = project_dir
            f.save(os.path.join(project_dir, filename))

            # Unzip the file
            with zipfile.ZipFile(os.path.join(project_dir, filename), 'r') as zip_ref:
                zip_ref.extractall(project_dir)
            # Get project_name from form fields
            project_name = request.form.get("project_name")
            # error message: missing project_name
            if not project_name:
                return error_response("Missing required field: project_name", 400)
            scan_args = [
                "/opt/sonar-scanner/bin/sonar-scanner",
                f"-Dsonar.projectBaseDir={project_dir}",
                f"-Dsonar.projectKey={project_key}",
                f"-Dsonar.projectName={project_name}",
                f"-Dsonar.sources=.",
                f"-Dsonar.login={header_token}"
            ]
        else:
            # --- Handle JSON (git_url or code) ---
            if not isinstance(data, dict):
                return error_response("Invalid request. Expecting file upload or JSON payload (git_url or code).")
            scan_args, cleanup_dir, err = prepare_scan(data, header_token)
            if err:
                return err
            project_name = data.get("project_name")

        result = subprocess.run(scan_args, capture_output=True, text=True, env=os.environ.copy())
        scanner_stdout = result.stdout
        scanner_stderr = result.stderr

        if "ANALYSIS SUCCESSFUL" not in scanner_stdout and "EXECUTION SUCCESS" not in scanner_stdout:
            return error_response("SonarScanner analysis failed.", 500,
                                  scanner_stdout=scanner_stdout, scanner_stderr=scanner_stderr)

        # Wait for the analysis to complete (polling)
        max_wait = 30
        poll_interval = 2
        waited = 0
        while waited < max_wait:
            report_data = get_sonar_report(project_key)
            project = report_data.get("project", {})
            if project.get("analysis_id") and project.get("status") and project.get("status") != "NONE":
                break
            time.sleep(poll_interval)
            waited += poll_interval
        else:
            if scanner_stderr:
                report_data["scanner_stderr_warnings"] = scanner_stderr
            report_data["warning"] = "Analysis is still processing. This report may be incomplete."
            return Response(
                json.dumps(report_data, ensure_ascii=False),
                status=202,
                mimetype='application/json'
            )

        if scanner_stderr:
            report_data["scanner_stderr_warnings"] = scanner_stderr

        return Response(
            json.dumps(report_data, ensure_ascii=False),
            status=200,
            mimetype='application/json'
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        return error_response("An unexpected server error occurred", 500, details=str(e))
    finally:
        if 'cleanup_dir' in locals() and cleanup_dir and os.path.exists(cleanup_dir):
            try:
                shutil.rmtree(cleanup_dir)
            except Exception:
                pass

# Endpoint: Get the report again for a project
@app.route('/report/<project_key>', methods=['GET'])
def get_report(project_key):

    # error message: missing required header
    if 'X-Sonar-Token' not in request.headers:
        return error_response("Missing required header: X-Sonar-Token", 401)
    header_token = request.headers.get('X-Sonar-Token')

    # error message: invalid SonarQube token in header
    if not header_token or (SONAR_TOKEN and header_token != SONAR_TOKEN):
        return error_response("Invalid SonarQube token in header.", 401)
    report_data = get_sonar_report(project_key)

    # error message: project not found or report not existed
    if "error" in report_data["project"]:
        return error_response("That report is not existed", 404)

    return Response(
        json.dumps(report_data, ensure_ascii=False),
        status=200,
        mimetype='application/json'
    )

# Endpoint: Test the API 
@app.route('/test', methods=['GET'])
def test_endpoint():
    return jsonify({"message": "Sonar API is running!", "sonar_host": SONAR_HOST}), 200

# 
if __name__ == '__main__':
    os.makedirs("/tmp/sonar_file_uploads", exist_ok=True)
    app.run(host='0.0.0.0', port=5000)