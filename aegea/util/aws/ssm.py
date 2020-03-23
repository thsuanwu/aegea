import os, sys, io, stat, shutil, platform, subprocess, tempfile, zipfile

import requests

from ... import logger, config

sm_plugin_bucket = "session-manager-downloads"

def download_session_manager_plugin_macos(target_path):
    sm_archive = io.BytesIO()
    sm_plugin_key = "plugin/latest/mac/sessionmanager-bundle.zip"
    res = requests.get("https://s3.amazonaws.com/{}/{}".format(sm_plugin_bucket, sm_plugin_key), stream=True)
    shutil.copyfileobj(res.raw, sm_archive)
    with zipfile.ZipFile(sm_archive) as zf, open(target_path, "wb") as fh:
        fh.write(zf.read("sessionmanager-bundle/bin/session-manager-plugin"))

def download_session_manager_plugin_linux(target_path, pkg_format="deb"):
    assert pkg_format in {"deb", "rpm"}
    sm_plugin_key = "plugin/latest/linux_64bit/session-manager-plugin." + pkg_format
    res = requests.get("https://s3.amazonaws.com/{}/{}".format(sm_plugin_bucket, sm_plugin_key), stream=True)
    with tempfile.TemporaryDirectory() as td:
        sm_archive_path = os.path.join(td, os.path.basename(sm_plugin_key))
        with open(sm_archive_path, "wb") as fh:
            shutil.copyfileobj(res.raw, fh)
        if pkg_format == "deb":
            subprocess.check_call(["dpkg", "-x", sm_archive_path, td])
        elif pkg_format == "rpm":
            command = "rpm2cpio '{}' | cpio --extract --make-directories --directory '{}'"
            subprocess.check_call(command.format(sm_archive_path, td), shell=True)
        shutil.move(os.path.join(td, "usr/local/sessionmanagerplugin/bin/session-manager-plugin"), target_path)

def ensure_session_manager_plugin():
    session_manager_dir = os.path.join(config.user_config_dir, "bin")
    PATH = os.environ.get("PATH", "") + ":" + session_manager_dir
    if shutil.which("session-manager-plugin", path=PATH):
        subprocess.check_call(["session-manager-plugin"], env=dict(os.environ, PATH=PATH))
    else:
        os.makedirs(session_manager_dir, exist_ok=True)
        target_path = os.path.join(session_manager_dir, "session-manager-plugin")
        if platform.system() == "Darwin":
            download_session_manager_plugin_macos(target_path=target_path)
        elif platform.linux_distribution()[0] == "Ubuntu":
            download_session_manager_plugin_linux(target_path=target_path)
        else:
            download_session_manager_plugin_linux(target_path=target_path, pkg_format="rpm")
        os.chmod(target_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        subprocess.check_call(["session-manager-plugin"], env=dict(os.environ, PATH=PATH))
    return shutil.which("session-manager-plugin", path=PATH)
