from setuptools import setup
import ppdeep

with open('README.md') as f:
	long_description = f.read()

setup(
	name='ppdeep',
	version=ppdeep.__version__,
	author='Marcin Ulikowski',
	author_email='marcin@ulikowski.pl',
	description='Pure-Python library for computing fuzzy hashes (ssdeep)',
	long_description=long_description,
	url='https://github.com/elceef/ppdeep',
	py_modules=['ppdeep'],
	classifiers=[
		'Programming Language :: Python :: 3',
		'License :: OSI Approved :: Apache Software License',
		'Operating System :: OS Independent',
	],
)
