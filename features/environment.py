import shutil


def after_scenario(context, scenario):
    working_dir = getattr(context, 'working_dir', None)
    if working_dir is not None:
        shutil.rmtree(working_dir)
