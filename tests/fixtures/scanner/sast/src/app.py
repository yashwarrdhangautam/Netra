import subprocess


def run_user_command(cmd):
    return subprocess.run(cmd, shell=True)  # noqa: S602 - intentionally vulnerable fixture


def calc(expr):
    return eval(expr)  # noqa: S307 - intentionally vulnerable fixture
