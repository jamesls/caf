from invoke import task, run

@task
def test():
    run('python setup.py test', pty=True)


@task
def clean():
    run("rm -rf build")
    run("rm -rf dist")
    run("rm -rf caf.egg-info")
    print("Cleaned up.")


@task
def build():
    clean()
    run("python setup.py sdist bdist_wheel")


@task
def publish(test=False):
    """Publish to the cheeseshop."""
    run("twine upload dist/*")


@task
def features():
    run("cd features && behave")
