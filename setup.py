import os
import re
import ast
from setuptools import setup


_version_re = re.compile(r'__version__\s+=\s+(.*)')
_root = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(_root, 'rikka/__init__.py')) as f:
    version = str(ast.literal_eval(_version_re.search(
        f.read()).group(1)))

with open(os.path.join(_root, 'requirements.txt')) as f:
    requirements = f.readlines()

with open(os.path.join(_root, 'README.md')) as f:
    readme = f.read()


setup(
    name='rikka',
    version=version,
    description='Expose localhost to public Internet',
    long_description=readme,
    long_description_content_type='text/markdown',
    url='https://github.com/Hanaasagi/rikka',
    author='Hanaasagi',
    author_email='ambiguous404@gmail.com',
    license='MIT',
    python_requires='>=3.6',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet',
        'Topic :: Internet :: Proxy Servers',
    ],
    packages=['rikka'],
    install_requires=requirements,
    entry_points="""
    [console_scripts]
    rklocal=rikka.local:main
    rkserver=rikka.server:main
    """,
)
